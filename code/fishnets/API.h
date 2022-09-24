// Copyright (c) Borislav Stanimirov
// SPDX-License-Identifier: MIT
//
#pragma once

#include <splat/symbol_export.h>

#if FISHNETS_SHARED
#   if BUILDING_FISHNETS
#       define FISHNETS_API SYMBOL_EXPORT
#   else
#       define FISHNETS_API SYMBOL_IMPORT
#   endif
#else
#   define FISHNETS_API
#endif
