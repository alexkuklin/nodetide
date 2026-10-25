# Offline tests of the selection logic. Run from the module directory: terraform test

variables {
  server_types = [
    {
      id = 10, name = "cax11", locations = [
        { name = "fsn1", available = true, is_deprecated = false },
        { name = "nbg1", available = true, is_deprecated = false },
        { name = "hel1", available = false, is_deprecated = false },
      ]
    },
    {
      id = 11, name = "cx23", locations = [
        { name = "fsn1", available = true, is_deprecated = false },
        { name = "nbg1", available = false, is_deprecated = false },
        { name = "hel1", available = true, is_deprecated = false },
      ]
    },
    {
      id = 12, name = "cpx11", locations = [
        { name = "fsn1", available = true, is_deprecated = true },
      ]
    },
    { id = 13, name = "cx33", locations = [] },
  ]
}

run "preferred_pair_wins" {
  variables {
    server_type_preference = ["cax11", "cx23"]
    location_preference    = ["fsn1", "nbg1"]
  }
  assert {
    condition     = output.chosen.type == "cax11" && output.chosen.location == "fsn1"
    error_message = "the first preference is available and should be chosen"
  }
}

run "next_location_before_next_type" {
  variables {
    server_type_preference = ["cax11", "cx23"]
    location_preference    = ["hel1", "nbg1"] # cax11 is sold out in hel1 but available in nbg1
  }
  assert {
    condition     = output.chosen.type == "cax11" && output.chosen.location == "nbg1"
    error_message = "should take the next location for the same type before the next type"
  }
}

run "moves_to_next_type_when_first_unusable" {
  variables {
    server_type_preference = ["cpx11", "cx23"]
    location_preference    = ["fsn1", "hel1"]
  }
  assert {
    condition     = output.chosen.type == "cx23" && output.chosen.location == "fsn1"
    error_message = "should skip the deprecated cpx11 and take cx23"
  }
}

run "sold_out_is_not_chosen" {
  variables {
    server_type_preference = ["cx23"]
    location_preference    = ["nbg1"]
  }
  assert {
    condition     = output.chosen == null
    error_message = "cx23 is temporarily unavailable in nbg1"
  }
  assert {
    condition     = contains(output.report, "cx23     nbg1  temporarily unavailable (sold out)")
    error_message = "the report should say why"
  }
}

run "deprecated_is_skipped_unless_allowed" {
  variables {
    server_type_preference = ["cpx11"]
    location_preference    = ["fsn1"]
  }
  assert {
    condition     = output.chosen == null && contains(output.report, "cpx11    fsn1  deprecated")
    error_message = "cpx11 is deprecated in fsn1"
  }
}

run "deprecated_allowed" {
  variables {
    server_type_preference = ["cpx11"]
    location_preference    = ["fsn1"]
    allow_deprecated       = true
  }
  assert {
    condition     = output.chosen.type == "cpx11"
    error_message = "allow_deprecated should accept it"
  }
}

run "no_location_detail_is_not_trusted" {
  variables {
    server_type_preference = ["cx33"]
    location_preference    = ["nbg1"]
  }
  assert {
    condition     = output.chosen == null && contains(output.report, "cx33     nbg1  not offered in this location")
    error_message = "without per-location detail availability cannot be verified"
  }
}

run "unknown_types_are_reported_not_fatal" {
  variables {
    server_type_preference = ["cx999", "cax11"]
    location_preference    = ["fsn1"]
  }
  assert {
    condition     = output.chosen.type == "cax11" && contains(output.report, "cx999    fsn1  unknown server type")
    error_message = "an unknown type is skipped and explained in the report"
  }
}

run "nothing_available_gives_null_and_hints" {
  variables {
    server_type_preference = ["cx23", "cax11"]
    location_preference    = ["hel1", "nbg1"]
  }
  assert {
    condition     = output.chosen.type == "cx23" && output.chosen.location == "hel1"
    error_message = "cx23 is available in hel1"
  }
}

run "hints_for_other_locations" {
  variables {
    server_type_preference = ["cx23", "cax11"]
    location_preference    = ["nbg1"]
  }
  assert {
    condition     = output.chosen.type == "cax11" && contains(output.available_elsewhere, "cx23@fsn1") && contains(output.available_elsewhere, "cx23@hel1")
    error_message = "should list where the preferred types are available outside the preference list"
  }
}
