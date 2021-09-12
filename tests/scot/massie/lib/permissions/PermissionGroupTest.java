package scot.massie.lib.permissions;

import org.assertj.core.api.ObjectAssert;
import org.junit.jupiter.api.Test;

public class PermissionGroupTest
{
    /*

    As permission groups are built around permission sets, primarily adding fallthrough permissions checking, the
    functionality tested by PermissionSetTest shouldn't need to be tested specifically.

    accessors
        getMostRelevantPermission
            permission that group has
            permission that group has and fallback group does
            permission that group has and default group has
            permission that group doesn't have, that fallback group does
            permission that group doesn't have, that default permissions group does
            permission that group doesn't have that fallback group and default group does
        getPermissionGroups
            empty
            with fallback groups specified
            empty but with default group specified
        toSaveString
            empty
            single permission
            multiple permissions
            single group
            multiple groups
            single group and permission
    mutators
        addPermissionGroup
            when empty
            when priority in middle of permission group priorities (ensure order)
        removePermissionGroup
            empty
            permission group not present
            permission group present (ensure callback is removed)
        clear
            empty
            permission groups present (ensure callbacks removed)
        reassignPriority
            to same
            to different (ensure group has new priority)
            to different (ensure group is in correct place in order of group that references this one and others)
     */
}
