-- The key of the machine a license was released from: it can still sign, so it is told to lock instead of waiting out the grace.
ALTER TABLE license ADD COLUMN released_alg TEXT;
ALTER TABLE license ADD COLUMN released_spki TEXT;
