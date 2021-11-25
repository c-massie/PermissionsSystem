package scot.massie.lib.permissions.events.args;

import scot.massie.lib.permissions.decorators.PermissionsRegistryWithEvents;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;

/**
 * Event args for when a permission is assigned or revoked.
 *
 * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
 *             to.
 */
public class PermissionEventArgs<ID extends Comparable<? super ID>>
        extends PermissionsChangedEventArgs<ID>
{
    /**
     * The permission that was associated with the action that raised this event.
     */
    final String permission;

    /**
     * Creates a new event args object.
     *
     * @param registry      The registry the event this eventargs object is being created for belongs to.
     * @param target        The type of entry in the registry that is being directly targeted.
     * @param userTargeted  Where a user is being targeted, the user that was targeted. If a user was not directly
     *                      targeted, this should always be null.
     * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
     *                      directly targeted, this should always be null.
     * @param permission    The permission that was assigned or revoked in the action that raised this event.
     */
    protected PermissionEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                  PermissionsChangedEventTarget target,
                                  ID userTargeted,
                                  String groupTargeted,
                                  String permission)
    {
        super(registry, target, userTargeted, groupTargeted);
        this.permission = permission;
    }


    /**
     * Gets the permission that was involved in this change.
     *
     * @return The permission that was involved in the action that raised the event.
     */
    public String getPermission()
    {
        return permission;
    }
}
