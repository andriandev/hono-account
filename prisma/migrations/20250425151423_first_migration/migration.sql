-- CreateTable
CREATE TABLE `tb_users` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `username` VARCHAR(100) NOT NULL,
    `password` VARCHAR(255) NOT NULL,
    `role` ENUM('admin', 'member', 'banned') NOT NULL DEFAULT 'member',
    `is_active` BOOLEAN NOT NULL DEFAULT false,
    `created_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `updated_at` DATETIME(3) NOT NULL,

    UNIQUE INDEX `tb_users_username_key`(`username`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `tb_apps` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `name` VARCHAR(100) NOT NULL,
    `url` VARCHAR(100) NOT NULL,

    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `tb_user_apps` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `user_id` INTEGER NOT NULL,
    `app_id` INTEGER NOT NULL,

    UNIQUE INDEX `tb_user_apps_user_id_app_id_key`(`user_id`, `app_id`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- CreateTable
CREATE TABLE `tb_auth` (
    `id` INTEGER NOT NULL AUTO_INCREMENT,
    `user_id` INTEGER NOT NULL,
    `ip_address` VARCHAR(60) NULL,
    `user_agent` VARCHAR(200) NULL,
    `login_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
    `is_active` BOOLEAN NOT NULL DEFAULT true,
    `token` VARCHAR(191) NOT NULL,

    UNIQUE INDEX `tb_auth_token_key`(`token`),
    PRIMARY KEY (`id`)
) DEFAULT CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

-- AddForeignKey
ALTER TABLE `tb_user_apps` ADD CONSTRAINT `tb_user_apps_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `tb_users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tb_user_apps` ADD CONSTRAINT `tb_user_apps_app_id_fkey` FOREIGN KEY (`app_id`) REFERENCES `tb_apps`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE `tb_auth` ADD CONSTRAINT `tb_auth_user_id_fkey` FOREIGN KEY (`user_id`) REFERENCES `tb_users`(`id`) ON DELETE CASCADE ON UPDATE CASCADE;
