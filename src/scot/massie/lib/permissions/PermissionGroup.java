package scot.massie.lib.permissions;

import scot.massie.lib.events.EventListener;
import scot.massie.lib.events.InvokableEvent;
import scot.massie.lib.events.SetEvent;
import scot.massie.lib.events.args.predefined.ValueReassignedEventArgs;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.function.Predicate;

/**
 * A collection of permissions (see {@link PermissionSet}) that may also reference other Permission groups, querying
 * them to check for the coverage of a given permission when not covered by this group directly.
 */
public class PermissionGroup
{
    //region Constants
    /**
     * <p>Comparator that sorts permission groups in order of priority, in order from highest to lowest.</p>
     *
     * <p>Where two permission groups share the same priority, order is indeterminate.</p>
     */
    public static final Comparator<PermissionGroup> priorityComparatorHighestFirst = (a, b) ->
    {
        int result = a.priorityIsLong ? (-Long  .compare(a.priorityAsLong, b.priorityAsLong))
                                      : (-Double.compare(a.priority,       b.priority      ));

        if(result != 0)
            return result;

        return a.name.compareTo(b.name);
    };

    /**
     * <p>A permission group to be provided as a default permission group for other permission groups.</p>
     *
     * <p>May not have a priority, contain any permissions, or reference any other permission groups, and never has nor
     * negates any permissions.</p>
     */
    public static final PermissionGroup emptyDefaultPermissions = new PermissionGroup("*", null)
    {
        final String cannotMutateErrorMsg = "Cannot mutate the empty default permission group.";

        @Override
        public void reassignPriority(long newPriority)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public void reassignPriority(double newPriority)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public Permission addPermission(String permissionAsString)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public Permission addPermissionWhileDeIndenting(String permissionAsString)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public Permission removePermission(String permissionPath)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public void addPermissionGroup(PermissionGroup permGroup)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public boolean removePermissionGroup(PermissionGroup permissionGroup)
        { throw new UnsupportedOperationException(cannotMutateErrorMsg); }

        @Override
        public boolean hasPermission(String permissionPath)
        { return false; }

        @Override
        public boolean hasPermissionOrAnyUnder(String permissionPath)
        { return false; }

        @Override
        public boolean hasPermissionOrAnyUnder(String permissionPath, Predicate<PermissionSet.PermissionWithPath> test)
        { return false; }

        @Override
        public boolean negatesPermission(String permissionPath)
        { return false; }

        @Override
        public String getPermissionArg(String permissionPath)
        { return null; }

        @Override
        public boolean hasGroupDirectly(String groupId)
        { return false; }

        @Override
        public boolean hasGroup(String groupId)
        { return false; }

        @Override
        protected PermissionSet.PermissionWithPath getMostRelevantPermission(String permissionAsString)
        { return null; }
    };
    //endregion

    //region Instance fields
    /**
     * The name, possibly used as a unique identifier, of the permission group.
     */
    final String name;

    /**
     * <p>The priority of this permission group, as a double.</p>
     *
     * <p>Priority determines the ordering of this group in the groups referenced by other groups, where higher priority
     * groups are queried before lower priority groups.</p>
     */
    double priority;

    /**
     * <p>The priority of this permission group, as a long.</p>
     *
     * <p>Priority determines the ordering of this group in the groups referenced by other groups, where higher priority
     * groups are queried before lower priority groups.</p>
     */
    long priorityAsLong;

    /**
     * Whether or not this permission group's priority was provided as, and should be read as, a long. If false, it
     * should be read as a double instead.
     */
    boolean priorityIsLong;

    /**
     * The store of permissions for this group. Queries of the permission group's permission are directed to this.
     */
    final PermissionSet permissionSet = new PermissionSet();

    /**
     * <p>Groups that should be referenced by this group.</p>
     *
     * <p>When this group is queried, permissions queries are checked against the stored permission set. If the
     * permission set doesn't cover the permission, (allowing *or* negating) the query is run against the referenced
     * groups until one is found that *does* cover the specified permission. These groups are checked in order from
     * higher priority to lower priority.</p>
     */
    final List<PermissionGroup> referencedGroups = new ArrayList<>();

    /**
     * <p>The permission group to check if this one and all others referenced do not cover a given permission.</p>
     *
     * <p>Queries defer to this only after this group's permission set and all other referenced groups have been
     * queried, and only if none of them have permissions covering the specified one.</p>
     */
    PermissionGroup defaultPermissions;

    /**
     * This PermissionGroup's listener for other PermissionGroup's priorities being changed.
     */
    EventListener<ValueReassignedEventArgs<Double>> priorityChangedListener
            = args -> PermissionGroup.this.sortPermissionGroups();
    //endregion

    //region Events
    /**
     * Event for when this event's priority changes.
     */
    protected final InvokableEvent<ValueReassignedEventArgs<Double>> priorityChanged = new SetEvent<>();
    //endregion

    //region Initialisation
    /**
     * <p>Creates a new permission group.</p>
     *
     * <p>When no priority is provided, it is 0 by default.</p>
     * @param name The name of the permission group. This may be used as a unique identifier.
     */
    public PermissionGroup(String name)
    { this(name, emptyDefaultPermissions, 0L); }

    /**
     * Creates a new permission group.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param priority The initial priority of this permission group.
     */
    public PermissionGroup(String name, long priority)
    { this(name, emptyDefaultPermissions, priority); }

    /**
     * Creates a new permission group.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param priority The initial priority of this permission group.
     */
    public PermissionGroup(String name, double priority)
    { this(name, emptyDefaultPermissions, priority); }

    /**
     * <p>Creates a new permission group.</p>
     *
     * <p>When no priority is provided, it is 0 by default.</p>
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param defaultPermissions The permission group to check if this one or any referenced by it do not cover a given
     *                           permission.
     */
    public PermissionGroup(String name, PermissionGroup defaultPermissions)
    { this(name, defaultPermissions, 0L); }

    /**
     * Creates a new permission group.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param defaultPermissions The permission group to check if this one or any referenced by it do not cover a given
     *                           permission.
     * @param priority The initial priority of this permission group.
     */
    public PermissionGroup(String name, PermissionGroup defaultPermissions, long priority)
    {
        this.name = name;
        this.defaultPermissions = defaultPermissions;
        this.priority = priority;
        this.priorityAsLong = priority;
        this.priorityIsLong = true;
    }

    /**
     * Creates a new permission group.
     * @param name The name of the permission group. This may be used as a unique identifier.
     * @param defaultPermissions The permission group to check if this one or any referenced by it do not cover a given
     *                           permission.
     * @param priority The initial priority of this permission group.
     */
    public PermissionGroup(String name, PermissionGroup defaultPermissions, double priority)
    {
        this.name = name;
        this.defaultPermissions = defaultPermissions;
        this.priority = priority;
        this.priorityAsLong = ((Double)priority).longValue();
        this.priorityIsLong = false;
    }
    //endregion

    //region Methods
    //region Accessors
    //region Getters
    /**
     * Gets this name of this permission group. This may be used as a unique identifier.
     * @return The name of this permission group.
     */
    public String getName()
    { return name; }

    /**
     * <p>Gets the priority of this permission group, as a double.</p>
     *
     * <p>The priority of a permission group defines its place in the order of permission groups referenced by other
     * permission groups, where a check for the allowance of a given permission, should the group not cover it, defers
     * to its referenced permission groups of higher priority before lower priority.
     * @return This permission group's priority as a double.</p>
     */
    public double getPriority()
    { return priority; }

    /**
     * <p>Gets the priority of this permission group, as a long.
     *
     * <p>The priority of a permission group defines its place in the order of permission groups referenced by other
     * permission groups, where a check for the allowance of a given permission, should the group not cover it, defers
     * to its referenced permission groups of higher priority before lower priority.
     * @return This permission group's priority as a long. Where this permission group's priority is given as a double,
     *         this returns the priority truncated to a long, as given by Double.longValue().
     */
    public long getPriorityAsLong()
    { return priorityAsLong; }

    /**
     * Gets a string representation of this permission group's priority. See {@link #getPriority()}.
     * @return A string repesentation of this permission group's priority. Where the priority is given as a double, this
     *         may include decimal places.
     */
    public String getPriorityAsString()
    { return priorityIsLong ? Long.toString(priorityAsLong) : Double.toString(priority); }

    /**
     * <p>Gets the {@link Permission} object contained within permission group's {@link PermissionSet} corresponding to
     * the given permission.</p>
     *
     * <p>Where this group's permission set contains no such permission, checks for this permission iteratively in each
     * permission group referenced by this permission, starting with highest priority and going to lowest.</p>
     *
     * <p>Where this group's permission set and referenced permission groups contain no such permission, checks for this
     * permission in the default permission group.</p>
     *
     * <p>Where the given permission is not covered by this permission group's permission set, any referenced permission
     * group, or the default permission group, returns null, to indicate that there is no permission relevant to the
     * given permission.</p>
     * @param permissionAsString The permission as a string to get the most relevant permission to.
     * @return The most relevant permission found among this permission group's permission set, the referenced
     *         permission groups, or the default group. If no relevant permission is found, returns null.
     */
    protected PermissionSet.PermissionWithPath getMostRelevantPermission(String permissionAsString)
    {
        PermissionSet.PermissionWithPath mrp = permissionSet.getMostRelevantPermission(permissionAsString);

        if(mrp != null)
            return mrp;

        for(PermissionGroup permGroup : referencedGroups)
        {
            mrp = permGroup.getMostRelevantPermission(permissionAsString);

            if(mrp != null)
                return mrp;
        }

        // Not an infinite recursive loop; eventually stops at a emptyDefaultPermissions where this method returns null.
        return defaultPermissions.getMostRelevantPermission(permissionAsString);
    }

    /**
     * <p>Gets the {@link Permission} object contained within permission group's {@link PermissionSet} corresponding to
     * the given permission.</p>
     *
     * <p>Where this group's permission set contains no such permission, checks for this permission iteratively in each
     * permission group referenced by this permission, starting with highest priority and going to lowest.</p>
     *
     * <p>Where this group's permission set and referenced permission groups contain no such permission, checks for this
     * permission in the default permission group.</p>
     *
     * <p>Where the given permission is not covered by this permission group's permission set, any referenced permission
     * group, or the default permission group, returns null, to indicate that there is no permission relevant to the
     * given permission.</p>
     * @param permissionAsStrings The permission as a list of nodes to get the most relevant permission to.
     * @return The most relevant permission found among this permission group's permission set, the referenced
     *         permission groups, or the default group. If no relevant permission is found, returns null.
     */
    protected PermissionSet.PermissionWithPath getMostRelevantPermission(List<String> permissionAsStrings)
    {
        PermissionSet.PermissionWithPath mrp = permissionSet.getMostRelevantPermission(permissionAsStrings);

        if(mrp != null)
            return mrp;

        for(PermissionGroup permGroup : referencedGroups)
        {
            mrp = permGroup.getMostRelevantPermission(permissionAsStrings);

            if(mrp != null)
                return mrp;
        }

        // Not an infinite recursive loop; eventually stops at a emptyDefaultPermissions where this method returns null.
        return defaultPermissions.getMostRelevantPermission(permissionAsStrings);
    }

    /**
     * <p>Gets the permission argument of the permission covering the given permission.</p>
     *
     * <p>The permission argument is given in the save string after the permission path, after all other suffixed,
     * prefixed with a colon. (':')</p>
     *
     * <p>Where the given permission is not covered by any permission of this permission group's {@link PermissionSet},
     * any referenced permission group, or the given default permission group, or where the permission covering it does
     * not have a permission argument provided, returns null instead.</p>
     *
     * <p>A permission is considered to cover another for the purposes of this where the other starts with the
     * dot-separated nodes of the first one, where the first one contains no additional dot-separated nodes not
     * contained in the other.</p>
     *
     * <p>This permission group is considered to cover a given permission for the purposes of this, where this
     * permission group's permission set, any of the referenced permission groups, or the given default permission
     * group, contains any permissions covering it, as defined above.</p>
     * @param permissionPath The permission to get the permission argument of.
     * @return The permission argument of the most relevant permission to the given one. Where there is no relevant
     *         permission, or where that permission does not have a string arg, returns null instead.
     */
    public String getPermissionArg(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return null;

        return mrp.getPermission().getArg();
    }

    /**
     * Gets all the relevant status information of the given permission pertaining to this permission group.
     * @param permissionPath The permission to get the status information of.
     * @return A PermissionStatus instance, detailing the path queried, whether or not this group had the given
     *         permission, and the permission arg if applicable.
     */
    public PermissionStatus getPermissionStatus(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        boolean hasPermission;
        String permArg;

        if(mrp == null)
        {
            hasPermission = false;
            permArg = null;
        }
        else
        {
            hasPermission = mrp.getPermission().permits();
            permArg = mrp.getPermission().getArg();
        }

        return new PermissionStatus(permissionPath, hasPermission, permArg);
    }

    /**
     * Gets permission statuses for all of the permissions directly in this permission group. Does not include
     * permissions in referenced permission groups or the default permission group.
     * @return Permission statuses for all of the permissions directly in this permission group.
     */
    public Collection<PermissionStatus> getPermissionStatuses()
    {
        Collection<PermissionStatus> result = new HashSet<>();

        for(String permPath : permissionSet.getPermissionsAsStrings(false))
        {
            Permission perm = permissionSet.getPermission(permPath);
            result.add(new PermissionStatus(permPath, perm.permits(), perm.getArg()));
        }

        return result;
    }

    /**
     * Gets the permission groups referenced by this permission.
     * @return A list of the permission groups referenced by this permission, in order from highest priority to lowest.
     */
    public List<PermissionGroup> getPermissionGroups()
    { return new ArrayList<>(referencedGroups); }

    /**
     * <p>Gets string representations of all permissions covered directly by this permission group.</p>
     *
     * <p>This ignored permissions in referenced permission groups or the default permission group.</p>
     *
     * <p>See {@link PermissionSet#getPermissionsAsStrings(boolean)}.</p>
     * @param includeArgs Whether or not to include the permission arguments in the string representations.
     * @return A list of string representations of the directly included permissions in this permission group, ordered
     *         by the alphabetical order of the nodes.
     */
    public List<String> getPermissionsAsStrings(boolean includeArgs)
    { return permissionSet.getPermissionsAsStrings(includeArgs); }
    //endregion

    //region State
    /**
     * <p>Checks whether this group has the given permission.</p>
     *
     * <p>A permission is considered to cover another for the purposes of this where the other starts with the
     * dot-separated nodes of the first one, where the first one contains no additional dot-separated nodes not
     * contained in the other.</p>
     *
     * <p>This permission group is considered to cover a given permission for the purposes of this, where this
     * permission group's permission set, any of the referenced permission groups, or the given default permission
     * group, contains any permissions covering it, as defined above.</p>
     * @param permissionPath The permission path to check for the coverage and allowance of.
     * @return True if the given permission path is allowed by this permission group. Otherwise, false.
     */
    public boolean hasPermission(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return false;

        return mrp.getPermission().permits();
    }

    /**
     * Checks whether this group has the given permission or any subpermission thereof.
     * @see #hasPermission(String)
     * @param permissionPath The permission path to check.
     * @return True if the given path or any covered permission is allowed by this permission group. Otherwise, false.
     */
    public boolean hasPermissionOrAnyUnder(String permissionPath)
    { return hasPermissionOrAnyUnder(permissionPath, x -> true); }

    /**
     * Checks whether this group has the given permission or any subpermission thereof, that satisfy the given
     * condition.
     * @see #hasPermission(String)
     * @param permissionPath The permission path to check.
     * @param check The condition for permissions to satisfy in order to be considered.
     * @return True if the given path or any covered permission is allowed and satisfies the given condition. Otherwise,
     *         false.
     */
    protected boolean hasPermissionOrAnyUnder(String permissionPath, Predicate<PermissionSet.PermissionWithPath> check)
    {
        // Add check for where all permissions under the path are included because it's covered by something that covers
        // it.
        // Add optimisation where everything's negated.

        if(permissionSet.hasPermissionOrAnyUnderWhere(permissionPath, check))
            return true;

        if(permissionSet.negatesPermission(permissionPath))
            return false;

        Collection<PermissionGroup> pgroupsAlreadyChecked = new ArrayList<>();

        Predicate<PermissionSet.PermissionWithPath> pgroupsAlreadyCheckedCheck = pwp ->
        {
            if(!check.test(pwp))
                return false;

            if(permissionSet.negatesPermission(pwp.getPath()))
                return false;

            for(PermissionGroup pgroup : pgroupsAlreadyChecked)
                if(pgroup.negatesPermission(pwp.getPath()))
                    return false;

            return true;
        };

        for(PermissionGroup permGroup : referencedGroups)
        {
            if(permGroup.hasPermissionOrAnyUnder(permissionPath, pgroupsAlreadyCheckedCheck))
                return true;

            pgroupsAlreadyChecked.add(permGroup);
        }

        // If statement is a step before returning false, not part of the final statement.
        //noinspection RedundantIfStatement
        if(defaultPermissions.hasPermissionOrAnyUnder(permissionPath, pgroupsAlreadyCheckedCheck))
            return true;

        return false;
    }

    /**
     * <p>Checks whether this group specifically negates the given permission.</p>
     *
     * <p>A permission is considered to cover another for the purposes of this where the other starts with the
     * dot-separated nodes of the first one, where the first one contains no additional dot-separated nodes not
     * contained in the other.</p>
     *
     * <p>This permission group is considered to cover a given permission for the purposes of this, where this
     * permission group's permission set, any of the referenced permission groups, or the given default permission
     * group, contains any permissions covering it, as defined above.</p>
     * @param permissionPath The permission path to check for the coverage and negation of.
     * @return True if the given permission path is specifically negated (and not simply not covered by) this permission
     *         group. Otherwise, false.
     */
    public boolean negatesPermission(String permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return false;

        return mrp.getPermission().negates();
    }

    /**
     * <p>Checks whether this group specifically negates the given permission.</p>
     *
     * <p>A permission is considered to cover another for the purposes of this where the other starts with the
     * dot-separated nodes of the first one, where the first one contains no additional dot-separated nodes not
     * contained in the other.</p>
     *
     * <p>This permission group is considered to cover a given permission for the purposes of this, where this
     * permission group's permission set, any of the referenced permission groups, or the given default permission
     * group, contains any permissions covering it, as defined above.</p>
     * @param permissionPath The permission path as a list of nodes to check for the coverage and negation of.
     * @return True if the given permission path is specifically negated (and not simply not covered by) this permission
     *         group. Otherwise, false.
     */
    protected boolean negatesPermission(List<String> permissionPath)
    {
        PermissionSet.PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp == null)
            return false;

        return mrp.getPermission().negates();
    }

    /**
     * <p>Whether or not this group directly or indirectly references a group with the given name.</p>
     *
     * <p>This takes into account groups references by groups references by this one, and so on.</p>
     * @param groupId The name of the group to check to see if this references.
     * @return True if this group or any group referenced by this group directly or indirectly references a group by the
     *         given name. Otherwise, false.
     */
    public boolean hasGroup(String groupId)
    {
        for(PermissionGroup pg : referencedGroups)
            if(pg.name.equals(groupId) || pg.hasGroup(groupId))
                return true;

        // If statement is a step before returning false, not part of the final statement.
        //noinspection RedundantIfStatement
        if(defaultPermissions.name.equals(groupId) || defaultPermissions.hasGroup(groupId))
            return true;

        return false;
    }

    /**
     * <p>Whether or not this group directly references a group with the given name.</p>
     *
     * <p>This ignores the groups referenced by the groups referenced by this one.</p>
     * @param groupId The name of the group to check to see if this references.
     * @return True if this group references a group by the given name. Otherwise, false.
     */
    public boolean hasGroupDirectly(String groupId)
    {
        for(PermissionGroup pg : referencedGroups)
            if(pg.name.equals(groupId))
                return true;

        return false;
    }

    /**
     * Gets whether or not this permission groups contains no permissions, and references only a single permissions
     * group.
     * @return True if this permission group has no permissions, and references exactly one other group. Otherwise,
     *         false.
     */
    boolean containsOnlyAGroup()
    { return (permissionSet.isEmpty()) && (referencedGroups.size() == 1); }

    /**
     * Gets whether or not this permission group contains any permissions, or references any groups. Ignores the default
     * group if provided.
     * @return True if this permission group contains no permissions and references no groups, apart from any provided
     *         default group. Otherwise, false.
     */
    public boolean isEmpty()
    { return permissionSet.isEmpty() && referencedGroups.isEmpty(); }
    //endregion

    //region String conversion
    /**
     * <p>Gets a multi-line string representation of this permission group.</p>
     *
     * <p>The returned string's first line is the permission group's header, made up of the name given to the permission
     * group, and, if non-default, the priority of this group.</p>
     *
     * <p>This is followed by the names of each referenced group's name, one-per-line, indented four spaces.</p>
     *
     * <p>This is followed by the string representation of the contained {@link PermissionSet}, as given by its own
     * {@link PermissionSet#toSaveString() toSaveString method}.</p>
     *
     * <p>The default permission group is not represented in the save string.</p>
     * @return A multi-lined string representation of this permission group.
     */
    public String toSaveString()
    {
        StringBuilder result = new StringBuilder((priority == 0) ? (name) : (name + ": " + getPriorityAsString()));

        if(containsOnlyAGroup())
            return result.append(" #").append(referencedGroups.get(0).getName()).toString();

        for(PermissionGroup permGroup : referencedGroups)
            result.append("\n    #").append(permGroup.getName());

        if(permissionSet.isEmpty())
            result.append("\n").append(permissionSet.toSaveString().replaceAll("(?m)^(?=.+)", "    "));

        return result.toString();
    }

    @Override public String toString()
    { return (priority == 0) ? (name) : (name + ": " + getPriorityAsString()); }
    //endregion
    //endregion

    //region Mutators
    //region Permissions
    /**
     * Adds a permission to this permission group.
     * @param permissionAsString The permission to add.
     * @return A permission representing the previously set permission at the given path, or null if there was none.
     * @throws ParseException If the provided permission was not parsable as a string.
     */
    public Permission addPermission(String permissionAsString) throws ParseException
    { return permissionSet.set(permissionAsString); }

    /**
     * <p>Adds a permission to this permission group, after having deïndented the string by 4 spaces.</p>
     *
     * <p>See {@link PermissionSet#setWhileDeIndenting(String)}.</p>
     * @param permissionAsString The permission to add.
     * @return A permission representing the previously set permission at the given path, or null if there was none.
     * @throws ParseException If the provided permission was not parsable as a string.
     */
    public Permission addPermissionWhileDeIndenting(String permissionAsString) throws ParseException
    { return permissionSet.setWhileDeIndenting(permissionAsString); }

    /**
     * Removes the specified permission from the permission group.
     * @see PermissionSet#remove(String)
     * @param permissionPath The permission to remove from this group.
     * @return A permission object representing the permission directly in the group at the given path, or null if there
     *         was none.
     */
    public Permission removePermission(String permissionPath)
    { return permissionSet.remove(permissionPath); }
    //endregion

    //region Permission groups
    /**
     * Adds a permission group to be referenced to this group. This will allow this permission group to query the
     * given permission group for permissions that this permission does not cover itself.
     * @param permGroup The permission group to add as a referenced permission group of this one.
     */
    public void addPermissionGroup(PermissionGroup permGroup)
    {
        int index = Collections.binarySearch(referencedGroups, permGroup, priorityComparatorHighestFirst);

        if(index >= 0)
            return;

        index = (index + 1) * -1;
        referencedGroups.add(index, permGroup);
        permGroup.priorityChanged.register(priorityChangedListener);
    }

    /**
     * Ensures that the permissions in this permission group are sorted in order from higher priority to lowest
     * priority.
     */
    protected void sortPermissionGroups()
    { referencedGroups.sort(priorityComparatorHighestFirst); }

    /**
     * Removes a permission group as a group referenced by this permission group. Disassociates it from this permission
     * group. This will mean the given permission group will no longer be able to be queried by this permission group
     * for permissions that this group itself does not have.
     * @param permissionGroup The permission group to remove as a group referenced by this one.
     * @return True if this permission group was modified as a result of this call. Otherwise, false.
     */
    public boolean removePermissionGroup(PermissionGroup permissionGroup)
    {
        if(referencedGroups.remove(permissionGroup))
        {
            permissionGroup.priorityChanged.deregister(priorityChangedListener);
            return true;
        }
        else
            return false;
    }
    //endregion

    //region Priority
    /**
     * Changes the priority of this permission group to the given priority.
     * @param newPriority The value to set this permission group's priority to.
     */
    public void reassignPriority(long newPriority)
    {
        double oldPriority = priority;
        priority = newPriority;
        priorityAsLong = newPriority;
        priorityIsLong = true;
        priorityChanged.invoke(new ValueReassignedEventArgs<>(oldPriority, priority));
    }

    /**
     * Changes the priority of this permission group to the given priority.
     * @param newPriority The value to set this permission group's priority to.
     */
    public void reassignPriority(double newPriority)
    {
        double oldPriority = priority;
        this.priority = newPriority;
        this.priorityAsLong = ((Double)newPriority).longValue();
        this.priorityIsLong = false;
        priorityChanged.invoke(new ValueReassignedEventArgs<>(oldPriority, newPriority));
    }
    //endregion

    //region Clear
    /**
     * Removes all permissions and referenced groups from this permission group. Does not affect the default group.
     */
    public void clear()
    {
        clearPermissions();
        clearGroups();
    }

    /**
     * Removes all referenced groups from this permission group. Does not affect the default group.
     */
    public void clearGroups()
    {
        for(PermissionGroup group : referencedGroups)
            group.priorityChanged.deregister(priorityChangedListener);

        referencedGroups.clear();
    }

    /**
     * Removes all permissions from this permission group. Does not affect any referenced groups or the default
     * permissions.
     */
    public void clearPermissions()
    { permissionSet.clear(); }
    //endregion
    //endregion
    //endregion
}
