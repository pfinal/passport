
```
CREATE TABLE IF NOT EXISTS `user` (
  `id` int NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `username` varchar(50) UNIQUE COMMENT '帐号',
  `email` varchar(255) UNIQUE COMMENT '邮箱',
  `mobile` varchar(50) UNIQUE COMMENT '手机',
  `password_hash` varchar(255) NOT NULL DEFAULT '',
  `change_password_at` DEFAULT NULL COMMENT '修改密码时间',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='User';

CREATE TABLE IF NOT EXISTS `token` (
  `id` int NOT NULL PRIMARY KEY AUTO_INCREMENT,
  `token` CHAR(32) UNIQUE NOT NULL COMMENT 'Token',
  `user_id` INT NOT NULL COMMENT 'UserId',
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Token';


CREATE TABLE IF NOT EXISTS oauth(
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `platform` VARCHAR(50) NOT NULL DEFAULT '', -- qq、weibo、wechat、github
  `appid` VARCHAR(100) NOT NULL DEFAULT '',
  `openid` VARCHAR(100) NOT NULL DEFAULT '',
  `user_id` INT NOT NULL,
  `created_at` DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
  `updated_at` DATETIME NOT NULL,
  unique (appid, openid, platform, user_id),
  KEY ind_user(user_id, platform)
)ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 AUTO_INCREMENT=1001 COMMENT='OAuth';
```
