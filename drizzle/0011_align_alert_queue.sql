-- Migration: align alert_queue table with current Drizzle schema
-- Applied manually on 2026-02-28
-- The table was created with an older schema that had different column names.

ALTER TABLE `alert_queue`
  CHANGE COLUMN `rawAlert` `rawJson` json DEFAULT NULL,
  CHANGE COLUMN `enqueuedBy` `queuedBy` int DEFAULT NULL,
  CHANGE COLUMN `createdAt` `queuedAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  DROP COLUMN `updatedAt`,
  ADD COLUMN `processedAt` timestamp NULL AFTER `queuedAt`,
  ADD COLUMN `completedAt` timestamp NULL AFTER `processedAt`,
  MODIFY COLUMN `status` enum('queued','processing','completed','failed','dismissed') NOT NULL DEFAULT 'queued',
  MODIFY COLUMN `alertId` varchar(128) NOT NULL,
  MODIFY COLUMN `ruleId` varchar(32) NOT NULL,
  MODIFY COLUMN `agentId` varchar(16) DEFAULT NULL,
  MODIFY COLUMN `agentName` varchar(128) DEFAULT NULL;

-- Fix alertId index: was UNIQUE (blocked re-queueing), now regular index
DROP INDEX `aq_alert_id_idx` ON `alert_queue`;
CREATE INDEX `aq_alertId_idx` ON `alert_queue` (`alertId`);
CREATE INDEX `aq_queuedAt_idx` ON `alert_queue` (`queuedAt`);
