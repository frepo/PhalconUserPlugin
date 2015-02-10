ALTER TABLE `portfolio`.`user` 
ADD COLUMN `user_type` INT NULL AFTER `updated_at`;

CREATE TABLE `portfolio`.`user_type` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `title` VARCHAR(45) NULL,
  `enabled` TINYINT NULL,
  `banned` TINYINT NULL,
  `visible` TINYINT NULL,
  PRIMARY KEY (`id`));
