CREATE TABLE users (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    name text,
    email text,
    auth_issuer text NOT NULL CHECK (auth_issuer <> ''),
    auth_provider_user_id text NOT NULL CHECK (auth_provider_user_id <> ''),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (auth_issuer, auth_provider_user_id)
);

CREATE TABLE chats (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    title text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (id, user_id)
);
CREATE INDEX chats_user ON chats(user_id);

CREATE TABLE messages (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    chat_id uuid NOT NULL REFERENCES chats(id),
    role text NOT NULL CHECK (role IN ('user', 'assistant')),
    content text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX messages_chat_time ON messages(chat_id, created_at, id);

CREATE TABLE resources (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id uuid NOT NULL REFERENCES users(id),
    chat_id uuid,
    name text NOT NULL,
    provider text NOT NULL CHECK (provider <> ''),
    account_scope text CHECK (account_scope <> ''),
    native_type text NOT NULL CHECK (native_type <> ''),
    provider_resource_id text CHECK (provider_resource_id <> ''),
    region text CHECK (region <> ''),
    os text,
    cpu_count integer CHECK (cpu_count > 0),
    memory_gb numeric CHECK (memory_gb > 0 AND memory_gb NOT IN ('NaN', 'Infinity')),
    storage_gb numeric CHECK (storage_gb > 0 AND storage_gb NOT IN ('NaN', 'Infinity')),
    status text NOT NULL DEFAULT 'pending',
    approved_config jsonb CHECK (jsonb_typeof(approved_config) = 'object'),
    approved_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    FOREIGN KEY (chat_id, user_id) REFERENCES chats(id, user_id),
    CHECK (provider_resource_id IS NULL OR account_scope IS NOT NULL),
    CHECK ((approved_config IS NULL) = (approved_at IS NULL))
);
CREATE INDEX resources_user ON resources(user_id);
CREATE INDEX resources_chat_owner ON resources(chat_id, user_id);
CREATE UNIQUE INDEX resources_native_identity ON resources(
    provider, account_scope, COALESCE(region, ''), native_type, provider_resource_id
) WHERE provider_resource_id IS NOT NULL;
