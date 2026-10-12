# Local-only image for running the legacy ERP (Perfex on CodeIgniter 3.1.11, ADR-0025).
# PHP 8.2 matches the version the live phpMyAdmin dump reports, so behaviour here
# should match production. This image is never deployed anywhere.
FROM php:8.2-apache

RUN apt-get update && apt-get install -y --no-install-recommends \
      libpng-dev libjpeg62-turbo-dev libfreetype6-dev \
      libzip-dev libicu-dev libxml2-dev libonig-dev \
      default-mysql-client unzip \
 && docker-php-ext-configure gd --with-freetype --with-jpeg \
 && docker-php-ext-install -j"$(nproc)" mysqli pdo_mysql gd zip intl exif \
 && a2enmod rewrite \
 && apt-get purge -y --auto-remove \
 && rm -rf /var/lib/apt/lists/*

# CodeIgniter routes through .htaccess, which needs AllowOverride All.
RUN printf '%s\n' \
    '<Directory /var/www/html>' \
    '    Options Indexes FollowSymLinks' \
    '    AllowOverride All' \
    '    Require all granted' \
    '</Directory>' \
    > /etc/apache2/conf-available/legacy-local.conf \
 && a2enconf legacy-local

COPY php-local.ini /usr/local/etc/php/conf.d/zz-legacy-local.ini
