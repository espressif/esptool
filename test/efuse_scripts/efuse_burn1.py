# flake8: noqa
# SPDX-FileCopyrightText: 2021-2022 Espressif Systems (Shanghai) CO LTD
#
# SPDX-License-Identifier: GPL-2.0-or-later

import json

config = json.load(args.configfiles[0])


assert args.index == 10, "Index should be 10"

for cmd in config["burn_efuses1"]:
    cmd = cmd.format(index=args.index)
    print(cmd)
    espefuse(esp, efuses, args, cmd)

assert args.index == 10, "Index should be 10"
