
```
CREATE TABLE IF NOT EXISTS `user` (
  `id` int NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `username` varchar(50) NOT NULL DEFAULT '' COMMENT '帐号',
  `password_hash` varchar(255) NOT NULL DEFAULT '',
  `email` varchar(255) NOT NULL DEFAULT '' COMMENT '邮箱',
  `mobile` varchar(50) NOT NULL DEFAULT '' COMMENT '手机',
  KEY `username` (`username`(20)),
  KEY `email` (`email`(20)),
  KEY `mobile` (`mobile`(11))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User';

CREATE TABLE IF NOT EXISTS `token` (
  `token` CHAR(32) NOT NULL COMMENT 'Token',
  `user_id` INT NOT NULL COMMENT 'UserId',
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(`token`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Token';
```
