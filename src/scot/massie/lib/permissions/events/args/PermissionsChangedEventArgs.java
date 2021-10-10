package scot.massie.lib.permissions.events.args;

import scot.massie.lib.events.args.EventArgs;
import scot.massie.lib.permissions.PermissionsRegistryWithEvents;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;

/**
 * Event args for when the contents of the permissions registry change.
 *
 * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
 *             to.
 */
public class PermissionsChangedEventArgs<ID extends Comparable<? super ID>> implements EventArgs
{
    /**
     * The registry this event belongs to. This event represents a change in the contents of this registry.
     */
    final PermissionsRegistryWithEvents<ID> registry;

    /**
     * What kind of entry of the registry is affected by this event.
     */
    final PermissionsChangedEventTarget target;

    /**
     * Where a user is targeted by this change, the user that was targeted. If a user was not targeted directly by
     * this change, this should always be null.
     */
    final ID userTargeted;

    /**
     * Where a group is targeted by this change, the group that was targeted. If a group was not targeted directly
     * by this change, this should always be null.
     */
    final String groupTargeted;

    /**
     * Creates a new event args object.
     *
     * @param registry      The registry the event this eventargs object is being created for belongs to.
     * @param target        The type of entry in the registry that is being directly targeted.
     * @param userTargeted  Where a user is being targeted, the user that was targeted. If a user was not directly
     *                      targeted, this should always be null.
     * @param groupTargeted Where a group is being targeted, the group that was targeted. If a group was not
     *                      directly targeted, this should always be null.
     */
    protected PermissionsChangedEventArgs(PermissionsRegistryWithEvents<ID> registry,
                                          PermissionsChangedEventTarget target,
                                          ID userTargeted,
                                          String groupTargeted)
    {
        this.registry = registry;
        this.target = target;
        this.userTargeted = userTargeted;
        this.groupTargeted = groupTargeted;
    }

    /**
     * Gets the type of entry of the registry that was targeted in the action that raised this event.
     *
     * @return The type of entry that was affected.
     */
    public PermissionsChangedEventTarget getTarget()
    {
        return target;
    }

    /**
     * Gets the ID of the user that was directly targeted by the action that raised this event.
     *
     * @return Where a user was directly targeted, the ID of the user that was targeted. If a user was not
     * *directly* targeted by the action that raised this event, null.
     */
    public ID getUserTargeted()
    {
        return userTargeted;
    }

    /**
     * Gets the ID of the group that was directly targeted by the action that raised this event.
     *
     * @return Where a group was directly targeted, the ID of the group that was targeted. If a group was not
     * *directly* targeted by the action that raised this event, null.
     */
    public String getGroupTargetedId()
    {
        return groupTargeted;
    }

    /**
     * Gets whether or not the user with the given ID was affected by the action that raised this event.
     *
     * @param userId The ID of the user to check whether or not they were affected by this change.
     * @return True if the user, any group the user has, (directly or indirectly) the default permissions, or any
     * group in the default permissions (directly or indirectly) was targeted by the change that raised this
     * event. Otherwise, false, as any other change wouldn't affect the permissions the user with the given
     * ID has, directly or indirectly.
     */
    public boolean userWasAffected(ID userId)
    {
        if(target == PermissionsChangedEventTarget.ALL || target == PermissionsChangedEventTarget.DEFAULT_PERMISSIONS)
            return true;

        if(target == PermissionsChangedEventTarget.USER)
            return userTargeted.equals(userId);

        // target == PermissionsChangedTarget.GROUP
        return registry.userHasGroup(userId, groupTargeted);
    }
}
