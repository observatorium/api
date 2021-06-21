create table if not exists metrics_rules
(
    tenant   varchar not null,
    name     varchar not null,
    interval integer,
    rules    text,
    created  timestamp with time zone default now(),
    updated  timestamp with time zone default now(),
    constraint metrics_rules_pk unique (tenant, name)
);
