drop table if exists scans;
create table scans(
  id integer primary key autoincrement,
  name text not null,
  date text not null,
  lastrun text,
  report text
);
drop table if exists hosts;
create table hosts(
  id integer primary key autoincrement,
  name text not null,
  address text not null,
  port integer not null,
  type text not null,
  username text not null,
  password text not null
);
drop table if exists iocs;
create table iocs(
  id integer primary key autoincrement,
  name text not null,
  date text not null,
  file text not null
);
drop table if exists scanshosts;
create table scanshosts(
  id integer primary key autoincrement,
  scanid integer not null,
  hostid integer not null
);
drop table if exists scansiocs;
create table scansiocs(
  id integer primary key autoincrement,
  scanid integer not null,
  iocid integer not null
);
