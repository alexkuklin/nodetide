variable "server_type_preference" {
  description = "Server type names in order of preference. Names the API does not know are skipped."
  type        = list(string)

  validation {
    condition     = length(var.server_type_preference) > 0
    error_message = "Give at least one server type."
  }
}

variable "location_preference" {
  description = "Hetzner locations (fsn1, nbg1, hel1, ash, hil, sin) in order of preference."
  type        = list(string)

  validation {
    condition     = length(var.location_preference) > 0
    error_message = "Give at least one location."
  }
}

variable "allow_deprecated" {
  description = "Also accept server types Hetzner has marked deprecated in a location."
  type        = bool
  default     = false
}

variable "server_types" {
  description = "Server types known to the API, with where each is offered."
  type = list(object({
    id   = number
    name = string
    locations = list(object({
      name          = string
      available     = bool
      is_deprecated = bool
    }))
  }))
}
