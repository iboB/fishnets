// fishnets
// Copyright (c) 2021-2022 Borislav Stanimirov
//
// Distributed under the MIT Software License
// See accompanying file LICENSE or copy at
// https://opensource.org/licenses/MIT
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
