import os
import shutil
import sys

def relocate_file(old_location, new_location):
    """
    keyring 0.8 changes the default location for storage of
    file-based keyring locations. This function is invoked to move
    files stored in the old location to the new location.

    TODO: remove this function for keyring 1.0.
    """
    if not os.path.exists(old_location):
        # nothing to do; no legacy file found
        return

    if os.path.exists(new_location):
        print >> sys.stderr, ("Password file found in legacy "
            "location\n  %(old_location)s\nand new location\n"
            "  %(new_location)s\nOld location will be ignored."
            % vars())
        return

    # ensure the storage path exists
    if not os.path.isdir(os.path.dirname(new_location)):
        os.makedirs(os.path.dirname(new_location))
    shutil.move(old_location, new_location)
