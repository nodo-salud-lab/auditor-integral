resource "aws_security_group" "abierto" {
  # ruleid: tf_ingreso_abierto
  ingress {
    from_port   = 22
    to_port     = 22
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_security_group" "web" {
  # ok: tf_ingreso_abierto
  ingress {
    from_port   = 443
    to_port     = 443
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_s3_bucket_acl" "b" {
  # ruleid: tf_bucket_publico
  acl = "public-read"
}

resource "aws_s3_bucket_public_access_block" "ok" {
  # ok: tf_bucket_publico
  block_public_acls = true
}

resource "aws_db_instance" "db" {
  # ruleid: tf_bd_publica
  publicly_accessible = true
  # ok: tf_bd_publica
  multi_az = true
  # ruleid: tf_sin_cifrado
  storage_encrypted = false
  # ok: tf_sin_cifrado
  deletion_protection = false
  # ruleid: tf_secreto_literal
  password = "superclave123"  # gitleaks:allow (caso de prueba de la regla semgrep; no es una credencial)
  # ok: tf_secreto_literal
  master_password = var.db_password
}
