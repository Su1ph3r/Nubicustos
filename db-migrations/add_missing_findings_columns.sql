-- Migration: Add missing Phase 1 columns to findings table
-- This fixes the "column does not exist" error on Linux installations

DO $$
BEGIN
    -- Add exploitability column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='exploitability') THEN
        ALTER TABLE findings ADD COLUMN exploitability VARCHAR(32) DEFAULT 'likely';
        RAISE NOTICE 'Added column: exploitability';
    END IF;

    -- Add asset_criticality column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='asset_criticality') THEN
        ALTER TABLE findings ADD COLUMN asset_criticality VARCHAR(16) DEFAULT 'medium';
        RAISE NOTICE 'Added column: asset_criticality';
    END IF;

    -- Add blast_radius column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='blast_radius') THEN
        ALTER TABLE findings ADD COLUMN blast_radius INTEGER DEFAULT 1;
        RAISE NOTICE 'Added column: blast_radius';
    END IF;

    -- Add recurrence_count column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='recurrence_count') THEN
        ALTER TABLE findings ADD COLUMN recurrence_count INTEGER DEFAULT 1;
        RAISE NOTICE 'Added column: recurrence_count';
    END IF;

    -- Add scoring_factors column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='scoring_factors') THEN
        ALTER TABLE findings ADD COLUMN scoring_factors JSONB DEFAULT '{}';
        RAISE NOTICE 'Added column: scoring_factors';
    END IF;

    -- Add threat_intel_enrichment column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='threat_intel_enrichment') THEN
        ALTER TABLE findings ADD COLUMN threat_intel_enrichment JSONB DEFAULT NULL;
        RAISE NOTICE 'Added column: threat_intel_enrichment';
    END IF;

    -- Add threat_intel_last_checked column if it doesn't exist
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='findings' AND column_name='threat_intel_last_checked') THEN
        ALTER TABLE findings ADD COLUMN threat_intel_last_checked TIMESTAMP;
        RAISE NOTICE 'Added column: threat_intel_last_checked';
    END IF;

    RAISE NOTICE 'Migration complete: All missing findings columns have been added';
END $$;
