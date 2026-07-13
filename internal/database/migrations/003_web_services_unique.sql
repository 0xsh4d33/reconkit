DELETE FROM web_services
WHERE id NOT IN (
    SELECT MIN(id)
    FROM web_services
    GROUP BY asset_id, url
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_web_services_asset_url
    ON web_services(asset_id, url);
