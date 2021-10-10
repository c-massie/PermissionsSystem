package scot.massie.lib.permissions.events.args;

import scot.massie.lib.permissions.PermissionsRegistryWithEvents;
import scot.massie.lib.permissions.events.PermissionsChangedEventTarget;

/**
 * Event args for when the contents of the registry are replaced with contents from a file.
 *
 * @param <ID> The type of the IDs used to identify users in the permissions registry this eventargs object belongs
 *             to.
 */
public class PermissionsLoadedEventArgs<ID extends Comparable<? super ID>> extends PermissionsChangedEventArgs<ID>
{
    /**
     * Creates a new event args object.
     *
     * @param registry The registry the event this event args object is for belongs to.
     */
    public PermissionsLoadedEventArgs(PermissionsRegistryWithEvents<ID> registry)
    {
        super(registry, PermissionsChangedEventTarget.ALL, null, null);
    }
}
