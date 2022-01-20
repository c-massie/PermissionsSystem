package scot.massie.lib.permissions;

import java.util.Collection;

public interface GroupBasedPermissionsRegistry<ID extends Comparable<? super ID>> extends PermissionsRegistry<ID>
{
    /**
     * Removes all groups from this registry that are currently unused by any users, other groups, or the default
     * permissions, and do not have any permissions or groups themselves. That is, groups that do not functionally
     * exist in this registry, but are left over from other operations.
     */
    void prune();

    /**
     * Removes the specified groups from this registry that are currently unused by any users, other groups, or the
     * default permissions, and do not have any permissions or groups themselves. That is, groups that do not
     * functionally exist in this registry, but are left over from other operations. Groups specified that *do* have any
     * permissions or other groups, or are had by any users, other groups, or the default permissions, are unaffected.
     * @param groupNames The names of the groups to remove if they match the aforementioned criteria.
     */
    void prune(Collection<String> groupNames);
}
