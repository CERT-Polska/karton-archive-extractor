# Copyright (C) 2017 Jurriaan Bremer.
# This file is part of SFlock - http://www.sflock.org/.
# See the file 'docs/LICENSE.txt' for copying permission.

from ..abstracts import Decoder
from ..misc import import_plugins

plugins = import_plugins(__file__, __name__, globals(), Decoder)
