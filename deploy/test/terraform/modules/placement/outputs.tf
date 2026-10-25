output "chosen" {
  description = "The first usable { type, location } pair, or null when nothing is available."
  value       = local.chosen
}

output "usable" {
  description = "Every usable pair, in order of preference."
  value       = [for c in local.usable : "${c.type}@${c.location}"]
}

output "report" {
  description = "One line per preferred pair saying why it is or is not usable."
  value       = local.report_lines
}

output "available_elsewhere" {
  description = "Preferred server types that are available in locations outside location_preference."
  value       = local.elsewhere
}
