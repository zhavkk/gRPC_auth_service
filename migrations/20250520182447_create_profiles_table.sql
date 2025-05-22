-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS profiles (
    id UUID PRIMARY KEY,
    username VARCHAR(255) UNIQUE NOT NULL,
    pass_hash TEXT NOT NULL,
    role VARCHAR(50) NOT NULL CHECK (role IN ('user', 'artist', 'admin')),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS users (
    profile_id UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    email VARCHAR(255) UNIQUE NOT NULL,
    gender BOOLEAN NOT NULL,
    country VARCHAR(100) NOT NULL,
    age SMALLINT NOT NULL ,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

CREATE TABLE IF NOT EXISTS artists (
    profile_id UUID PRIMARY KEY REFERENCES profiles(id) ON DELETE CASCADE,
    author VARCHAR(255) NOT NULL,
    producer VARCHAR(255),
    country VARCHAR(100) NOT NULL,
    description TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT now(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT now()
);

ALTER TABLE artists
ADD CONSTRAINT uq_artists_author UNIQUE (author);

CREATE INDEX idx_profiles_username ON profiles(username);
CREATE INDEX idx_users_email ON users(email);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS artists;
DROP TABLE IF EXISTS profiles;
-- +goose StatementEnd
