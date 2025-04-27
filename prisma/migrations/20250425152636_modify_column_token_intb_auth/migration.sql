-- DropIndex
DROP INDEX `tb_auth_token_key` ON `tb_auth`;

-- AlterTable
ALTER TABLE `tb_auth` MODIFY `token` VARCHAR(300) NOT NULL;
