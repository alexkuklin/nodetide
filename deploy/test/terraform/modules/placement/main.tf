# Picks a (server type, location) pair that Hetzner can really provide right now.
#
# Availability is limited and changes by the hour, so a hard-coded pair is a gamble. The API reports,
# per server type and location, whether the type is currently available there (`available` is false
# when it is temporarily sold out) and whether it is deprecated there. Candidates are tried type by
# type in preference order, each across the locations in preference order.

locals {
  types = { for t in var.server_types : t.name => t }

  candidates = flatten([
    for type_name in var.server_type_preference : [
      for loc in var.location_preference : {
        type     = type_name
        location = loc
        known    = contains(keys(local.types), type_name)
        offered = contains(keys(local.types), type_name) ? anytrue([
          for l in local.types[type_name].locations : l.name == loc
        ]) : false
        available = contains(keys(local.types), type_name) ? anytrue([
          for l in local.types[type_name].locations : l.name == loc && l.available
        ]) : false
        usable = contains(keys(local.types), type_name) ? anytrue([
          for l in local.types[type_name].locations :
          l.name == loc && l.available && (var.allow_deprecated || !l.is_deprecated)
        ]) : false
      }
    ]
  ])

  usable = [for c in local.candidates : c if c.usable]
  chosen = length(local.usable) > 0 ? local.usable[0] : null

  report_lines = [
    for c in local.candidates :
    format("%-8s %-5s %s", c.type, c.location,
      !c.known ? "unknown server type" :
      !c.offered ? "not offered in this location" :
      !c.available ? "temporarily unavailable (sold out)" :
      !c.usable ? "deprecated" :
      "available"
    )
  ]

  # preferred types that ARE available in locations outside the preference list
  elsewhere = distinct(flatten([
    for type_name in var.server_type_preference : [
      for l in(contains(keys(local.types), type_name) ? local.types[type_name].locations : []) :
      format("%s@%s", type_name, l.name)
      if l.available && (var.allow_deprecated || !l.is_deprecated) && !contains(var.location_preference, l.name)
    ]
  ]))
}
