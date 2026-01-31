CREATE TABLE IF NOT EXISTS attack_logs (
    id BIGSERIAL PRIMARY KEY,
    event_time TIMESTAMP NOT NULL,
    src_addr INET,
    src_port VARCHAR(10),
    dst_addr INET,
    dst_port VARCHAR(10),
    protocol VARCHAR(20),
    attack_type VARCHAR(256),
    attack_detail VARCHAR(256),
    response_type VARCHAR(256)
);

CREATE INDEX idx_event_time ON attack_logs(event_time);
CREATE INDEX idx_src_addr ON attack_logs(src_addr);