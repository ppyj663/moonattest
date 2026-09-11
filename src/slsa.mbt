///|
/// Errors returned while reading the SLSA provenance predicate.
pub suberror SlsaError {
  SlsaNotObject
  SlsaMissingField(String)
  SlsaInvalidField(String)
}

///|
fn slsa_required_string(
  object : Map[String, Json],
  field : String,
) -> Result[String, SlsaError] {
  match object.get(field) {
    None => Err(SlsaMissingField(field))
    Some(String(value)) => Ok(value)
    Some(_) => Err(SlsaInvalidField(field))
  }
}

///|
fn slsa_object(
  object : Map[String, Json],
  field : String,
) -> Result[Map[String, Json], SlsaError] {
  match object.get(field) {
    None => Err(SlsaMissingField(field))
    Some(Object(value)) => Ok(value)
    Some(_) => Err(SlsaInvalidField(field))
  }
}

///|
/// Extract the builder identity and source repository from a SLSA v1 predicate.
/// The source reader accepts both the common `repository.url` shape and the
/// SLSA-compatible `source.uri` shape used by some generators.
pub fn parse_slsa_provenance(
  statement : Statement,
) -> Result[Provenance, SlsaError] {
  guard statement.predicate is Object(predicate) else {
    return Err(SlsaNotObject)
  }
  let run_details = match slsa_object(predicate, "runDetails") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let builder = match slsa_object(run_details, "builder") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let builder_id = match slsa_required_string(builder, "id") {
    Ok(value) => value
    Err(SlsaMissingField(_)) =>
      return Err(SlsaMissingField("runDetails.builder.id"))
    Err(error) => return Err(error)
  }
  let build_definition = match slsa_object(predicate, "buildDefinition") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let external_parameters = match
    slsa_object(build_definition, "externalParameters") {
    Ok(value) => value
    Err(error) => return Err(error)
  }
  let source_uri = match external_parameters.get("repository") {
    Some(Object(repository)) =>
      match slsa_required_string(repository, "url") {
        Ok(value) => value
        Err(SlsaMissingField(_)) =>
          return Err(
            SlsaMissingField(
              "buildDefinition.externalParameters.repository.url",
            ),
          )
        Err(error) => return Err(error)
      }
    Some(_) =>
      return Err(
        SlsaInvalidField("buildDefinition.externalParameters.repository"),
      )
    None =>
      match external_parameters.get("source") {
        Some(Object(source)) =>
          match slsa_required_string(source, "uri") {
            Ok(value) => value
            Err(SlsaMissingField(_)) =>
              return Err(
                SlsaMissingField(
                  "buildDefinition.externalParameters.source.uri",
                ),
              )
            Err(error) => return Err(error)
          }
        Some(_) =>
          return Err(
            SlsaInvalidField("buildDefinition.externalParameters.source"),
          )
        None =>
          return Err(
            SlsaMissingField(
              "buildDefinition.externalParameters.repository.url",
            ),
          )
      }
  }
  Ok(Provenance::new(builder_id, source_uri))
}
