use bitcoin::ScriptBuf;
use secp256k1::rand::{prelude::IndexedRandom, rng, seq::SliceRandom, Rng};
use serde::{Deserialize, Serialize};

use super::{error::WalletError, storage::AddressType};

/// User/configurable privacy settings for Electrum queries.
///
/// These settings control how many real wallet scripts are mixed with how many
/// decoy scripts before querying an Electrum server.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyConfig {
    /// If false, Electrum queries behave like normal direct wallet queries.
    pub enabled: bool,

    /// Number of decoy scripts to add to each Electrum query batch.
    pub decoy_pool_range: (usize, usize),

    /// Number of real wallet scripts per batch.
    pub real_batch_range: (usize, usize),

    /// Maximum number of decoy scripts persisted in the wallet file.
    pub max_decoy_cache_size: usize,

    /// Fraction of decoys replaced by fresh decoys each sync/batch.
    pub decoy_rotation_range: (f64, f64),

    /// Maximum age for a cached decoy before forced retirement.
    pub max_decoy_age_secs: u64,

    /// Per-decoy random usage limit range.
    pub retire_after_uses_range: (u32, u32),
}

impl Default for PrivacyConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            decoy_pool_range: (34, 67),
            real_batch_range: (3, 9),
            max_decoy_cache_size: 500,
            decoy_rotation_range: (0.27, 0.53),
            max_decoy_age_secs: 3 * 24 * 60 * 60,
            retire_after_uses_range: (5, 15),
        }
    }
}

/// One decoy script saved in the wallet file.
///
/// A decoy is a valid wallet-derived script that is queried only for privacy cover.
/// It must never be treated as a real wallet UTXO unless the wallet explicitly owns
/// and tracks it through the normal real-script path.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecoyEntry {
    /// Script pubkey queried as privacy cover.
    pub script: ScriptBuf,

    /// HD derivation index used to create this decoy script.
    pub hd_index: u32,

    /// Address type used for this decoy script.
    pub address_type: AddressType,

    /// Whether this decoy was derived from the internal/change keychain.
    pub is_internal: bool,

    /// Number of query batches this decoy has appeared in.
    pub times_used: u32,

    /// Unix timestamp when this decoy was created.
    pub created_at: u64,

    /// Maximum number of times this decoy may be reused before retirement.
    pub retire_after_uses: u32,
}

impl DecoyEntry {
    /// Create a new decoy cache entry.
    pub fn new(
        script: ScriptBuf,
        hd_index: u32,
        address_type: AddressType,
        is_internal: bool,
        retire_after_uses: u32,
    ) -> Self {
        Self {
            script,
            hd_index,
            address_type,
            is_internal,
            times_used: 0,
            created_at: now_unix_secs(),
            retire_after_uses,
        }
    }
}

/// Persistent cache of decoy scripts.
///
/// This is intentionally persisted so every sync does not look like a totally
/// fresh wallet with brand-new never-seen scripts.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct DecoyCache {
    /// Cached decoy entries available for reuse.
    pub entries: Vec<DecoyEntry>,

    /// Maximum number of decoys retained in the cache.
    pub max_cache_size: usize,

    /// Range controlling what fraction of decoys should be fresh per selection.
    pub rotation_range: (f64, f64),

    /// Maximum age in seconds before a decoy is retired.
    pub max_age_secs: u64,

    /// Range for per-entry reuse limits.
    pub retire_after_uses_range: (u32, u32),
}

impl Default for DecoyCache {
    fn default() -> Self {
        Self::from_privacy_config(&PrivacyConfig::default())
    }
}

impl DecoyCache {
    /// Build an empty decoy cache using the given privacy configuration.
    pub fn from_privacy_config(config: &PrivacyConfig) -> Self {
        Self {
            entries: Vec::new(),
            max_cache_size: config.max_decoy_cache_size,
            rotation_range: config.decoy_rotation_range,
            max_age_secs: config.max_decoy_age_secs,
            retire_after_uses_range: config.retire_after_uses_range,
        }
    }

    /// Select decoys for one Electrum query batch.
    ///
    /// This returns a mix of reused cached decoys and fresh decoys.
    /// Fresh decoys are provided by the wallet layer because the wallet owns the
    /// HD derivation logic.
    pub fn select_decoys_for_batch<F>(
        &mut self,
        needed: usize,
        derive_fresh_decoy: &mut F,
    ) -> Result<Vec<ScriptBuf>, WalletError>
    where
        F: FnMut() -> Result<DecoyEntry, WalletError>,
    {
        if needed == 0 {
            return Ok(Vec::new());
        }

        let mut rng = rng();
        let now = now_unix_secs();

        // 1. Retire expired decoys.
        let max_age_secs = self.max_age_secs;
        self.entries.retain(|entry| {
            entry.times_used < entry.retire_after_uses
                && now.saturating_sub(entry.created_at) < max_age_secs
        });

        // 2. Decide fresh vs reused split.
        let rotation_pct = draw_f64_inclusive(&mut rng, self.rotation_range);
        let fresh_count = ((needed as f64) * rotation_pct).floor() as usize;
        let reused_target = needed.saturating_sub(fresh_count);

        // 3. Reuse random cached decoys.
        let reused_count = reused_target.min(self.entries.len());
        let mut indices: Vec<usize> = (0..self.entries.len()).collect();
        indices.shuffle(&mut rng);
        indices.truncate(reused_count);

        let mut result = Vec::with_capacity(needed);

        for idx in indices {
            let entry = &mut self.entries[idx];
            entry.times_used = entry.times_used.saturating_add(1);
            result.push(entry.script.clone());
        }

        // 4. Generate fresh decoys if cache was not enough.
        let fresh_needed = needed.saturating_sub(result.len());

        for _ in 0..fresh_needed {
            let mut entry = derive_fresh_decoy()?;

            // Randomize retirement per entry to avoid uniform behaviour.
            entry.retire_after_uses = draw_u32_inclusive(&mut rng, self.retire_after_uses_range);

            result.push(entry.script.clone());
            self.entries.push(entry);
        }

        // 5. Trim cache if it grew too large.
        self.trim(now);

        Ok(result)
    }

    fn trim(&mut self, now: u64) {
        while self.entries.len() > self.max_cache_size {
            let Some(idx) = self
                .entries
                .iter()
                .enumerate()
                .max_by_key(|(_, entry)| {
                    entry.times_used as u64 * 1000 + now.saturating_sub(entry.created_at)
                })
                .map(|(idx, _)| idx)
            else {
                break;
            };

            self.entries.swap_remove(idx);
        }
    }
}

/// Script item passed to Electrum after mixing real wallet scripts with decoys.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateQueryItem {
    /// Script pubkey included in the Electrum query.
    pub script: ScriptBuf,

    /// True when this script belongs to the wallet and its results should be used.
    pub is_real: bool,
}

/// Build shuffled private query batches.
///
/// The wallet/Electrum sync layer should query all returned scripts, but only
/// process results where `is_real == true`.
#[allow(dead_code)]
pub fn build_private_query_batches<F>(
    real_scripts: &[ScriptBuf],
    decoy_cache: &mut DecoyCache,
    privacy: &PrivacyConfig,
    derive_fresh_decoy: &mut F,
) -> Result<Vec<Vec<PrivateQueryItem>>, WalletError>
where
    F: FnMut() -> Result<DecoyEntry, WalletError>,
{
    if real_scripts.is_empty() {
        return Ok(Vec::new());
    }

    if !privacy.enabled {
        return Ok(vec![real_scripts
            .iter()
            .cloned()
            .map(|script| PrivateQueryItem {
                script,
                is_real: true,
            })
            .collect()]);
    }

    let mut rng = rng();
    let mut batches = Vec::new();
    let mut offset = 0;

    while offset < real_scripts.len() {
        let real_count = draw_usize_inclusive(&mut rng, privacy.real_batch_range).max(1);
        let end = (offset + real_count).min(real_scripts.len());

        let mut batch: Vec<PrivateQueryItem> = real_scripts[offset..end]
            .iter()
            .cloned()
            .map(|script| PrivateQueryItem {
                script,
                is_real: true,
            })
            .collect();

        let decoy_count = draw_usize_inclusive(&mut rng, privacy.decoy_pool_range);
        let decoys = decoy_cache.select_decoys_for_batch(decoy_count, derive_fresh_decoy)?;

        batch.extend(decoys.into_iter().map(|script| PrivateQueryItem {
            script,
            is_real: false,
        }));

        batch.shuffle(&mut rng);
        batches.push(batch);

        offset = end;
    }

    Ok(batches)
}

/// Build shuffled private query batches from an already-generated decoy pool.
///
/// This is used inside `ElectrumBackend::list_unspent`, where the backend has
/// access to real watched scripts and decoy scripts, but not to the wallet's
/// persistent `DecoyCache`.
pub fn build_private_query_batches_from_pool(
    real_scripts: &[ScriptBuf],
    decoy_pool: &[ScriptBuf],
    privacy: &PrivacyConfig,
) -> Vec<Vec<PrivateQueryItem>> {
    if real_scripts.is_empty() {
        return Vec::new();
    }

    let mut rng = rng();

    if !privacy.enabled || decoy_pool.is_empty() {
        const FALLBACK_BATCH_SIZE: usize = 200;

        return real_scripts
            .chunks(FALLBACK_BATCH_SIZE)
            .map(|chunk| {
                chunk
                    .iter()
                    .cloned()
                    .map(|script| PrivateQueryItem {
                        script,
                        is_real: true,
                    })
                    .collect()
            })
            .collect();
    }

    let mut batches = Vec::new();
    let mut offset = 0;

    while offset < real_scripts.len() {
        let real_count = draw_usize_inclusive(&mut rng, privacy.real_batch_range).max(1);
        let end = (offset + real_count).min(real_scripts.len());

        let mut batch: Vec<PrivateQueryItem> = real_scripts[offset..end]
            .iter()
            .cloned()
            .map(|script| PrivateQueryItem {
                script,
                is_real: true,
            })
            .collect();

        let decoy_count = draw_usize_inclusive(&mut rng, privacy.decoy_pool_range);

        for _ in 0..decoy_count {
            if let Some(script) = decoy_pool.choose(&mut rng) {
                batch.push(PrivateQueryItem {
                    script: script.clone(),
                    is_real: false,
                });
            }
        }

        batch.shuffle(&mut rng);
        batches.push(batch);

        offset = end;
    }

    batches
}

/// Draw a random reuse limit for a new decoy entry.
#[allow(dead_code)]
pub fn random_retire_after_uses(config: &PrivacyConfig) -> u32 {
    let mut rng = rng();
    draw_u32_inclusive(&mut rng, config.retire_after_uses_range)
}

fn draw_usize_inclusive(rng: &mut impl Rng, range: (usize, usize)) -> usize {
    let min = range.0.min(range.1);
    let max = range.0.max(range.1);
    rng.random_range(min..=max)
}

fn draw_u32_inclusive(rng: &mut impl Rng, range: (u32, u32)) -> u32 {
    let min = range.0.min(range.1);
    let max = range.0.max(range.1);
    rng.random_range(min..=max)
}

fn draw_f64_inclusive(rng: &mut impl Rng, range: (f64, f64)) -> f64 {
    let min = range.0.min(range.1);
    let max = range.0.max(range.1);
    rng.random_range(min..=max)
}

fn now_unix_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::opcodes::all::OP_RETURN;
    use bitcoin::script::Builder;

    fn fake_script(n: u8) -> ScriptBuf {
        Builder::new()
            .push_opcode(OP_RETURN)
            .push_slice([n])
            .into_script()
    }

    fn fake_decoy_entry(n: u8) -> DecoyEntry {
        DecoyEntry::new(fake_script(n), n as u32, AddressType::P2WPKH, false, 10)
    }

    #[test]
    fn private_batches_include_all_real_scripts() {
        let real_scripts: Vec<ScriptBuf> = (0..20).map(fake_script).collect();
        let decoy_pool: Vec<ScriptBuf> = (100..120).map(fake_script).collect();
        let privacy = PrivacyConfig::default();

        let batches = build_private_query_batches_from_pool(&real_scripts, &decoy_pool, &privacy);

        let collected_real: Vec<ScriptBuf> = batches
            .iter()
            .flatten()
            .filter(|item| item.is_real)
            .map(|item| item.script.clone())
            .collect();

        assert_eq!(collected_real.len(), real_scripts.len());

        for script in real_scripts {
            assert!(collected_real.contains(&script));
        }
    }

    #[test]
    fn private_batches_add_decoys_when_pool_available() {
        let real_scripts: Vec<ScriptBuf> = (0..10).map(fake_script).collect();
        let decoy_pool: Vec<ScriptBuf> = (100..130).map(fake_script).collect();
        let privacy = PrivacyConfig::default();

        let batches = build_private_query_batches_from_pool(&real_scripts, &decoy_pool, &privacy);

        let real_count = batches.iter().flatten().filter(|item| item.is_real).count();

        let decoy_count = batches
            .iter()
            .flatten()
            .filter(|item| !item.is_real)
            .count();

        assert_eq!(real_count, real_scripts.len());
        assert!(decoy_count > 0);
    }

    #[test]
    fn private_batches_fallback_to_real_only_when_privacy_disabled() {
        let real_scripts: Vec<ScriptBuf> = (0..10).map(fake_script).collect();
        let decoy_pool: Vec<ScriptBuf> = (100..130).map(fake_script).collect();

        let privacy = PrivacyConfig {
            enabled: false,
            ..PrivacyConfig::default()
        };

        let batches = build_private_query_batches_from_pool(&real_scripts, &decoy_pool, &privacy);

        let real_count = batches.iter().flatten().filter(|item| item.is_real).count();

        let decoy_count = batches
            .iter()
            .flatten()
            .filter(|item| !item.is_real)
            .count();

        assert_eq!(real_count, real_scripts.len());
        assert_eq!(decoy_count, 0);
    }

    #[test]
    fn decoy_cache_generates_and_reuses_decoys() {
        let privacy = PrivacyConfig::default();
        let mut cache = DecoyCache::from_privacy_config(&privacy);
        let mut next = 1u8;

        let mut derive_fresh_decoy = || {
            let entry = fake_decoy_entry(next);
            next = next.saturating_add(1);
            Ok(entry)
        };

        let first = cache
            .select_decoys_for_batch(20, &mut derive_fresh_decoy)
            .unwrap();

        let second = cache
            .select_decoys_for_batch(20, &mut derive_fresh_decoy)
            .unwrap();

        assert_eq!(first.len(), 20);
        assert_eq!(second.len(), 20);
        assert!(!cache.entries.is_empty());
        assert!(cache.entries.len() <= cache.max_cache_size);
    }
}
