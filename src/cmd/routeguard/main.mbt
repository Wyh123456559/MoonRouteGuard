///|
extern "js" fn node_read_file(path : String) -> String =
  #| function(path) {
  #|   try {
  #|     globalThis.__routeguardReadError = "";
  #|     return require("node:fs").readFileSync(path, "utf8");
  #|   } catch (error) {
  #|     globalThis.__routeguardReadError = error instanceof Error
  #|       ? error.message
  #|       : String(error);
  #|     return "";
  #|   }
  #| }

///|
extern "js" fn node_last_read_error() -> String =
  #| function() {
  #|   return globalThis.__routeguardReadError || "";
  #| }

///|
extern "js" fn node_write_error(message : String) -> Unit =
  #| function(message) {
  #|   process.stderr.write(message);
  #| }

///|
extern "js" fn node_write_output(message : String) -> Unit =
  #| function(message) {
  #|   process.stdout.write(message);
  #| }

///|
extern "js" fn node_set_exit_code(code : Int) -> Unit =
  #| function(code) {
  #|   process.exitCode = code;
  #| }

///|
struct CliConfig {
  before_path : String
  after_path : String
  routes_path : String
  fail_on_new_invalid : Bool
  json : Bool
  slurm_path : String?
}

///|
fn usage() -> String {
  "usage: routeguard [--json] [--fail-on-new-invalid] [--slurm POLICY.json] BEFORE.csv AFTER.csv ROUTES.csv"
}

///|
fn parse_cli(argv : Array[String]) -> Result[CliConfig, String] {
  let mut start = 0
  let mut fail_on_new_invalid = false
  let mut json = false
  let mut slurm_path : String? = None
  while start < argv.length() && argv[start].has_prefix("--") {
    if argv[start] == "--fail-on-new-invalid" && !fail_on_new_invalid {
      fail_on_new_invalid = true
    } else if argv[start] == "--json" && !json {
      json = true
    } else if argv[start] == "--slurm" && slurm_path is None {
      if start + 1 >= argv.length() ||
        argv[start + 1].is_empty() ||
        argv[start + 1].has_prefix("--") {
        return Err(usage())
      }
      slurm_path = Some(argv[start + 1])
      start = start + 1
    } else {
      return Err(usage())
    }
    start = start + 1
  }
  if argv.length() != start + 3 {
    return Err(usage())
  }
  for path in argv[start:] {
    if path.is_empty() || path.has_prefix("--") {
      return Err(usage())
    }
  }
  Ok({
    before_path: argv[start],
    after_path: argv[start + 1],
    routes_path: argv[start + 2],
    fail_on_new_invalid,
    json,
    slurm_path,
  })
}

///|
fn format_diagnostics(
  path : String,
  diagnostics : Array[@lib.CsvDiagnostic],
) -> String {
  let buffer = StringBuilder()
  for diagnostic in diagnostics {
    buffer.write_string("\{path}:\{diagnostic.line}: \{diagnostic.message}\n")
  }
  buffer.to_string()
}

///|
struct CliReport {
  text : String
  json : String
  newly_invalid : Int
}

///|
fn assess_csv_inputs(
  before_path : String,
  before_source : String,
  after_path : String,
  after_source : String,
  routes_path : String,
  routes_source : String,
  slurm_path : String?,
  slurm_source : String?,
) -> Result[CliReport, String] {
  let before = @lib.parse_vrp_csv(before_source)
  let after = @lib.parse_vrp_csv(after_source)
  let routes = @lib.parse_route_csv(routes_source)
  let errors = StringBuilder()
  errors.write_string(format_diagnostics(before_path, before.diagnostics))
  errors.write_string(format_diagnostics(after_path, after.diagnostics))
  errors.write_string(format_diagnostics(routes_path, routes.diagnostics))
  let error_text = errors.to_string()
  if !error_text.is_empty() {
    return Err(error_text)
  }
  let diff = @lib.compare_snapshots(before.records, after.records)
  let mut previous_vrps = before.records.map(record => record.vrp)
  let mut current_vrps = after.records.map(record => record.vrp)
  let mut previous_policy : @lib.SlurmApplyResult? = None
  let mut current_policy : @lib.SlurmApplyResult? = None
  match slurm_source {
    Some(source) => {
      let policy = match @lib.parse_slurm_json(source) {
        Ok(value) => value
        Err(message) =>
          return Err("\{slurm_path.unwrap_or("SLURM")}: \{message}\n")
      }
      let before_applied = policy.apply(previous_vrps)
      let after_applied = policy.apply(current_vrps)
      previous_vrps = before_applied.vrps
      current_vrps = after_applied.vrps
      previous_policy = Some(before_applied)
      current_policy = Some(after_applied)
    }
    None => ()
  }
  let impact = @lib.assess_snapshot_impact(
    routes.routes,
    previous_vrps,
    current_vrps,
  )
  let report = StringBuilder()
  report.write_string("VRP snapshot: \{diff.summary()}\n")
  match previous_policy {
    Some(before_applied) => {
      report.write_string("SLURM before: \{before_applied.summary()}\n")
      match current_policy {
        Some(after_applied) =>
          report.write_string("SLURM after: \{after_applied.summary()}\n")
        None => ()
      }
    }
    None => ()
  }
  report.write_string("Route impact: \{impact.summary()}\n")
  let mut newly_invalid = 0
  for change in impact.changed {
    if change.current.validity == @lib.Invalid {
      newly_invalid = newly_invalid + 1
      report.write_string("NEW INVALID: ")
    }
    report.write_string(change.summary())
    report.write_string("\n")
  }
  report.write_string("Newly invalid routes: \{newly_invalid}\n")
  let json = match previous_policy {
    Some(before_applied) =>
      match current_policy {
        Some(after_applied) =>
          @lib.write_assessment_json(
            diff,
            impact,
            slurm=(before_applied, after_applied),
          )
        None => @lib.write_assessment_json(diff, impact)
      }
    None => @lib.write_assessment_json(diff, impact)
  }
  Ok({ text: report.to_string(), json, newly_invalid, })
}

///|
fn read_text(path : String) -> Result[String, String] {
  let source = node_read_file(path)
  let read_error = node_last_read_error()
  if !read_error.is_empty() {
    return Err("routeguard: unable to read \{path}: \{read_error}")
  }
  Ok(source)
}

///|
fn main {
  let argv = @env.args()
  let inputs : Array[String] = []
  for index = 2; index < argv.length(); index = index + 1 {
    inputs.push(argv[index])
  }
  let config = match parse_cli(inputs) {
    Ok(config) => config
    Err(message) => {
      node_write_error("\{message}\n")
      node_set_exit_code(2)
      return
    }
  }
  let before = match read_text(config.before_path) {
    Ok(source) => source
    Err(message) => {
      node_write_error("\{message}\n")
      node_set_exit_code(2)
      return
    }
  }
  let after = match read_text(config.after_path) {
    Ok(source) => source
    Err(message) => {
      node_write_error("\{message}\n")
      node_set_exit_code(2)
      return
    }
  }
  let routes = match read_text(config.routes_path) {
    Ok(source) => source
    Err(message) => {
      node_write_error("\{message}\n")
      node_set_exit_code(2)
      return
    }
  }
  let slurm_source = match config.slurm_path {
    Some(path) =>
      match read_text(path) {
        Ok(source) => Some(source)
        Err(message) => {
          node_write_error("\{message}\n")
          node_set_exit_code(2)
          return
        }
      }
    None => None
  }
  match
    assess_csv_inputs(
      config.before_path,
      before,
      config.after_path,
      after,
      config.routes_path,
      routes,
      config.slurm_path,
      slurm_source,
    ) {
    Ok(report) => {
      if config.json {
        node_write_output("\{report.json}\n")
      } else {
        node_write_output(report.text)
      }
      if config.fail_on_new_invalid && report.newly_invalid > 0 {
        node_set_exit_code(3)
      }
    }
    Err(message) => {
      node_write_error(message)
      node_set_exit_code(2)
    }
  }
}
