-- remove non essential fields from model.

ALTER TABLE models DROP COLUMN default_series, DROP COLUMN migration_controller_id, DROP COLUMN is_controller, DROP COLUMN cores, 
 DROP COLUMN machines, DROP COLUMN units, DROP COLUMN type, DROP COLUMN status_status, DROP COLUMN status_info, DROP COLUMN status_data, 
 DROP COLUMN status_since, DROP COLUMN status_version, DROP COLUMN sla_level, DROP COLUMN sla_owner;
