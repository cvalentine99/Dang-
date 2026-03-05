-- Migration 0012: Create sensitive_access_audit table for agentKey disclosure policy
-- This table logs every access to sensitive resources (agent keys, etc.)
-- Required for compliance: the agentKey reveal flow is fail-closed —
-- if this insert fails, the key is NOT returned.

CREATE TABLE IF NOT EXISTS `sensitive_access_audit` (
  `id` int AUTO_INCREMENT NOT NULL,
  `userId` int NOT NULL,
  `resourceType` varchar(64) NOT NULL,
  `resourceId` varchar(128) NOT NULL,
  `action` varchar(32) NOT NULL,
  `ipAddress` varchar(45),
  `userAgent` text,
  `createdAt` timestamp NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT `sensitive_access_audit_id` PRIMARY KEY(`id`)
);

CREATE INDEX `saa_userId_idx` ON `sensitive_access_audit` (`userId`);
CREATE INDEX `saa_resourceType_idx` ON `sensitive_access_audit` (`resourceType`);
CREATE INDEX `saa_resourceId_idx` ON `sensitive_access_audit` (`resourceId`);
CREATE INDEX `saa_createdAt_idx` ON `sensitive_access_audit` (`createdAt`);
