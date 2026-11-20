#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
# /**
#  * @file    userspace/tests/net/run.sh
#  * @brief   Guest network test phase selection.
#  * @author  frankischilling
#  * @date    2026-11-18
#  *
#  * Selects the normal, queue pressure, or fault input for the installed network
#  * test.
#  *
#  * Copyright (C) 2026 frankischilling
#  *
#  * This program is free software: you can redistribute it and/or modify
#  * it under the terms of the GNU General Public License as published by
#  * the Free Software Foundation, either version 3 of the License, or
#  * (at your option) any later version.
#  *
#  * This program is distributed in the hope that it will be useful,
#  * but WITHOUT ANY WARRANTY; without even the implied warranty of
#  * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
#  * GNU General Public License for more details.
#  *
#  * You should have received a copy of the GNU General Public License
#  * along with this program. If not, see <https://gnu.org/licenses/>.
#  */
set -eu
case "${AXIOM64_PHASE:-verify}" in
    pressure) /bin/net-tests pressure ;;
    queue) /bin/net-tests 65570 ;;
    error) /bin/net-tests fault-length ;;
    invalid) /bin/net-tests fault-id ;;
    *) /bin/net-tests 16 ;;
esac
echo AXIOM64_TESTS_PASS
