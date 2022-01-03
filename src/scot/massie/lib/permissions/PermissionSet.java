package scot.massie.lib.permissions;

import scot.massie.lib.collections.iterables.ListUtils;
import scot.massie.lib.collections.trees.RecursiveTree;
import scot.massie.lib.collections.trees.Tree;
import scot.massie.lib.collections.trees.TreeEntry;
import scot.massie.lib.collections.trees.TreePath;
import scot.massie.lib.utils.wrappers.MutableWrapper;

import java.text.ParseException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.List;
import java.util.Objects;
import java.util.function.Predicate;
import java.util.stream.Stream;

/**
 * A set of {@link Permission permissions} arranged in a string-keyed tree, where permissions are considered to "cover"
 * (apply to) all permissions under them in the tree.
 */
public final class PermissionSet
{
    //region Inner classes
    /**
     * <p>A pairing of a permission with the path leading to that permission.</p>
     *
     * <p>Exists primarily because Java doesn't support named tuples.</p>
     */
    public static final class PermissionWithPath
    {
        /**
         * Creates a new PermissionWithPath by pairing the given path with the given permission.
         * @param path The path to pair with the permission.
         * @param perm The permission to pair with the path.
         */
        public PermissionWithPath(List<String> path, Permission perm)
        {
            this.path = path;
            this.permission = perm;
        }

        /**
         * Creates a new PermissionWithPath from an existing appropriate TreeEntry object,
         * @param treeEntry The tree entry to produce a PermissionWithPath from.
         */
        public PermissionWithPath(TreeEntry<String, Permission> treeEntry)
        { this(treeEntry.getPath().getNodes(), treeEntry.getItem()); }

        /**
         * The path leading to the permission.
         */
        private final List<String> path;

        /**
         * The permission.
         */
        private final Permission permission;

        /**
         * Gets the path of this pairing.
         * @return The path contained within this pairing.
         */
        public List<String> getPath()
        { return path; }

        /**
         * Gets the permission of this pairing.
         * @return The path contained within this pairing.
         */
        public Permission getPermission()
        { return permission; }
    }
    //endregion

    //region Constants
    /**
     * <p>Comparator that compares paths.</p>
     *
     * <p>This comparator goes through each node in the paths in order until it finds one that's different in the two
     * provided paths. It then returns the result of comparing those two nodes.</p>
     *
     * <p>Where all nodes are the same, the paths are considered the same.</p>
     *
     * <p>Where one path is shorter than another but paths are both the same up to that point, the shorter path is
     * considered to come first.</p>
     */
    private static final Comparator<List<String>> PATH_COMPARATOR = (a, b) ->
    {
        for(int i = 0; i < a.size(); i++)
        {
            if(i >= b.size())
                return 1;

            String ia = a.get(i);
            String ib = b.get(i);
            int comparison = ia.compareTo(ib);

            if(comparison != 0)
                return comparison;
        }

        if(a.size() == b.size())
            return 0;

        return -1;
    };
    //endregion

    //region Instance fields
    /**
     * <p>The tree of exact permissions. Permissions in this tree cover only themselves exactly.</p>
     *
     * <p>Permission paths are the paths to the permission in this tree or {@link #descendantPermissionTree}.</p>
     */
    final Tree<String, Permission> exactPermissionTree = new RecursiveTree<>();

    /**
     * <p>The tree of descendant permissions. Permissions in this tree cover only permissions descending from them.</p>
     *
     * <p>Permission paths are the paths to the permission in this tree or {@link #exactPermissionTree}.</p>
     */
    final Tree<String, Permission> descendantPermissionTree = new RecursiveTree<>();
    //endregion

    //region Methods
    //region Static utils
    //region String manipulation
    static String[] splitPath(String permissionPath)
    { return permissionPath.split("\\.", -1); }

    static String applyPermissionToPathStringWithoutArg(String path, Permission perm)
    { return perm.negates() ? ("-" + path) : path; }

    static String applyPermissionToPathString(String path, Permission perm)
    {
        if(perm.negates())
            path = "-" + path;

        if(perm.hasArg())
        {
            String arg = perm.getArg();

            path += (arg.contains("\n")) ? (":\n" + arg.replaceAll("(?m)^(?=.+)", "    "))
                            : (": " + perm.getArg());
        }

        return path;
    }

    static String applyPermissionToPathString(String path, Permission perm, boolean includeArg)
    { return includeArg ? applyPermissionToPathString(path, perm) : applyPermissionToPathStringWithoutArg(path, perm); }
    //endregion
    //endregion

    //region Accessors
    //region Tests as a whole
    /**
     * Checks whether or not this permission set contains any permissions.
     * @return True if this contains any permissions. Otherwise, false.
     */
    public boolean hasAny()
    { return !isEmpty(); }

    /**
     * Checks whether or not this permission set is empty.
     * @return True if this contains no permissions. Otherwise, false.
     */
    public boolean isEmpty()
    {
        return exactPermissionTree                  .isEmpty()
            && descendantPermissionTree             .isEmpty();
    }
    //endregion

    //region Getters
    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path, paired with the path it's
     * at.
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path, paired with the path of that
     *         permission in this permission set, in the form of a {@link PermissionWithPath}, or null if no permission
     *         in this permission set applies to the given permission path.
     */
    public PermissionWithPath getMostRelevantPermission(String permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return getMostRelevantPermission(Arrays.asList(splitPath(permissionPath)));
    }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path, paired with the path it's
     * at.
     * @param permissionPath The permission path, as a list of nodes, to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path, paired with the path of that
     *         permission in this permission set, in the form of a {@link PermissionWithPath}, or null if no permission
     *         in this permission set applies to the given permission path.
     */
    public PermissionWithPath getMostRelevantPermission(List<String> permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        TreePath<String> pPath = new TreePath<>(permissionPath);
        Permission relevantPerm = exactPermissionTree.getAtOrNull(pPath);

        if(relevantPerm != null)
            return new PermissionWithPath(permissionPath, relevantPerm);

        List<TreeEntry<String, Permission>> relevantEntries = descendantPermissionTree.getEntriesAlong(pPath);
        int relevantEntryIndex = ListUtils.lastIndexWhere(relevantEntries,
                                                          x -> x.getPath().size() != permissionPath.size());

        return (relevantEntryIndex < 0) ? (null) : (new PermissionWithPath(relevantEntries.get(relevantEntryIndex)));
    }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path, paired with the path it's
     * at.
     * @param permissionPath The permission path, as an array of nodes, to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path, paired with the path of that
     *         permission in this permission set, in the form of a {@link PermissionWithPath}, or null if no permission
     *         in this permission set applies to the given permission path.
     */
    public PermissionWithPath getMostRelevantPermission(String... permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return getMostRelevantPermission(Arrays.asList(permissionPath));
    }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path.
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path.
     */
    public Permission getPermission(String permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return getPermission(Arrays.asList(splitPath(permissionPath)));
    }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path.
     * @param permissionPath The permission path, as a list of nodes, to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path.
     */
    public Permission getPermission(List<String> permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        PermissionWithPath mostRelevant = getMostRelevantPermission(permissionPath);

        if(mostRelevant == null)
            return null;

        return mostRelevant.getPermission();
    }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path.
     * @param permissionPath The permission path, as an array of nodes, to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path.
     */
    public Permission getPermission(String... permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return getPermission(Arrays.asList(permissionPath));
    }
    //endregion

    //region Check permissions
    //region has permission
    //region has permission normally
    /**
     * Checks if the permissions in this permission set allow the provided permission.
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to test.
     * @return True if the permission path is allowed. Otherwise, false.
     */
    public boolean hasPermission(String permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return hasPermission(Arrays.asList(splitPath(permissionPath)));
    }

    /**
     * Checks if the permissions in this permission set allow the provided permission.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if the permission path is allowed. Otherwise, false.
     */
    public boolean hasPermission(List<String> permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && (mrp.permission.permits());
    }

    /**
     * Checks if the permissions in this permission set allow the provided permission.
     * @param permissionPath The permission path to test, as an array of nodes.
     * @return True if the permission path is allowed. Otherwise, false.
     */
    public boolean hasPermission(String... permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return hasPermission(Arrays.asList(permissionPath));
    }
    //endregion

    //region has permission or any under
    /**
     * Checks if this permission set has a permission or any subpermissions of it.
     * @param permissionPath The permission path to test.
     * @return True if this permission set has any permissions starting with the provided path. (by nodes) Otherwise,
     *         false.
     */
    public boolean hasPermissionOrAnyUnder(String permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return hasPermissionOrAnyUnder(Arrays.asList(splitPath(permissionPath)));
    }

    /**
     * Checks if this permission set has a permission or any subpermissions of it.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if this permission set has any permissions starting with the provided path. (by nodes) Otherwise,
     *         false.
     */
    public boolean hasPermissionOrAnyUnder(List<String> permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(mrp != null && mrp.getPermission().permits())
            return true;

        TreePath<String> pPath = new TreePath<>(permissionPath);

        for(Permission p : exactPermissionTree.getItemsAtAndUnder(pPath))
            if(p.permits())
                return true;

        for(Permission p : descendantPermissionTree.getItemsAtAndUnder(pPath))
            if(p.permits())
                return true;

        return false;
    }

    /**
     * Checks if this permission set has a permission or any subpermissions of it.
     * @param permissionPath The permission path to test, as an array of nodes.
     * @return True if this permission set has any permissions starting with the provided path. (by nodes) Otherwise,
     *         false.
     */
    public boolean hasPermissionOrAnyUnder(String... permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return hasPermissionOrAnyUnder(Arrays.asList(permissionPath));
    }

    /**
     * Checks if this permission set has a permission or any subpermissions of it that satisfies a given condition.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @param condition The condition for permissions to satisfy to be considered.
     * @return True if this permission set has any permissions starting with the provided path (by nodes) that satisfy
     *         the given condition. Otherwise, false.
     */
    public boolean hasPermissionOrAnyUnderWhere(String permissionPath, Predicate<PermissionWithPath> condition)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return hasPermissionOrAnyUnderWhere(Arrays.asList(splitPath(permissionPath)), condition);
    }

    /**
     * Checks if this permission set has a permission or any subpermissions of it that satisfies a given condition.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @param condition The condition for permissions to satisfy to be considered.
     * @return True if this permission set has any permissions starting with the provided path (by nodes) that satisfy
     *         the given condition. Otherwise, false.
     */
    public boolean hasPermissionOrAnyUnderWhere(List<String> permissionPath, Predicate<PermissionWithPath> condition)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);

        if(condition == null)
            condition = x -> true;

        if(mrp != null && mrp.getPermission().permits())
            if(condition.test(mrp))
                return true;

        TreePath<String> pPath = new TreePath<>(permissionPath);

        for(TreeEntry<String, Permission> p : exactPermissionTree.getEntriesAtAndUnder(pPath))
            if(p.getItem().permits() && condition.test(new PermissionWithPath(p.getPath().getNodes(), p.getItem())))
            { return true; }

        for(TreeEntry<String, Permission> p : descendantPermissionTree.getEntriesAtAndUnder(pPath))
            if(p.getItem().permits() && condition.test(new PermissionWithPath(p.getPath().getNodes(), p.getItem())))
            { return true; }

        return false;
    }

    /**
     * Checks if this permission set has a permission or any subpermissions of it that satisfies a given condition.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @param condition The condition for permissions to satisfy to be considered.
     * @return True if this permission set has any permissions starting with the provided path (by nodes) that satisfy
     *         the given condition. Otherwise, false.
     */
    public boolean hasPermissionOrAnyUnderWhere(String[] permissionPath, Predicate<PermissionWithPath> condition)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return hasPermissionOrAnyUnderWhere(Arrays.asList(permissionPath), condition);
    }
    //endregion

    //region has permission exactly
    /**
     * Checks if this permissions set explicitly allows the provided permission path, and the provided permission path
     * is not simply allowed by inference of another permission that covers it.
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to test.
     * @return True if the permission path is explicitly allowed. That is, if this specific path has been added as a
     *         permission, and isn't simply allowed by inference from another permission that covers this one.
     *         Otherwise, false.
     */
    public boolean hasPermissionExactly(String permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");

        if(permissionPath.trim().endsWith(".*"))
        {
            permissionPath = permissionPath.substring(0, permissionPath.length() - 2);
            return hasPermissionExactly(Arrays.asList(splitPath(permissionPath)), descendantPermissionTree);
        }

        return hasPermissionExactly(splitPath(permissionPath));
    }

    /**
     * Checks if this permissions set explicitly allows the provided permission path, and the provided permission path
     * is not simply allowed by inference of another permission that covers it.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if the permission path is explicitly allowed. That is, if this specific path has been added as a
     *         permission, and isn't simply allowed by inference from another permission that covers this one.
     *         Otherwise, false.
     */
    public boolean hasPermissionExactly(List<String> permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return hasPermissionExactly(permissionPath, exactPermissionTree);
    }

    /**
     * Checks if this permissions set explicitly allows the provided permission path, and the provided permission path
     * is not simply allowed by inference of another permission that covers it.
     * @param permissionPath The permission path to test, as an array of nodes.
     * @return True if the permission path is explicitly allowed. That is, if this specific path has been added as a
     *         permission, and isn't simply allowed by inference from another permission that covers this one.
     *         Otherwise, false.
     */
    public boolean hasPermissionExactly(String... permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return hasPermissionExactly(Arrays.asList(permissionPath), exactPermissionTree);
    }

    /**
     * Checks if the given permission trees directly contain the given permission path.
     * @param permissionPath The path to check for.
     * @param permTree The regular permission tree to check.
     * @return True if the given trees contain a direct permitting permission at the given path. Otherwise,
     *         false.
     */
    private static boolean hasPermissionExactly(List<String> permissionPath, Tree<String, Permission> permTree)
    {
        Permission perm = permTree.getAtOrNull(new TreePath<>(permissionPath));
        return (perm != null) && (perm.permits()) && (!perm.isIndirect());
    }
    //endregion
    //endregion

    //region negates permission
    //region negates permission normally
    /**
     * Checks if this permissions set negates the provided permission path. (and doesn't simply not cover it.)
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to test.
     * @return True if the permission path is negated. Otherwise, (including if this permission set doesn't allow the
     *         provided permission path by simple omission) false.
     */
    public boolean negatesPermission(String permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return negatesPermission(Arrays.asList(splitPath(permissionPath)));
    }

    /**
     * Checks if this permissions set negates the provided permission path. (and doesn't simply not cover it.)
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if the permission path is negated. Otherwise, (including if this permission set doesn't allow the
     *         provided permission path by simple omission) false.
     */
    public boolean negatesPermission(List<String> permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && (mrp.permission.negates());
    }

    /**
     * Checks if this permissions set negates the provided permission path. (and doesn't simply not cover it.)
     * @param permissionPath The permission path to test, as an array of nodes.
     * @return True if the permission path is negated. Otherwise, (including if this permission set doesn't allow the
     *         provided permission path by simple omission) false.
     */
    public boolean negatesPermission(String... permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return negatesPermission(Arrays.asList(permissionPath));
    }
    //endregion

    //region negates permission exactly
    /**
     * Checks if this permissions set specifically negates the provided permission path. That is, if the permission path
     * has been specifically added as one to negate.
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to test.
     * @return True if the permission path is explicitly negated. That is, if the path has been specifically added to
     *         this permission set as one that should be negated, and its negation isn't simply inferred from other
     *         permission that covers it. Otherwise, false.
     */
    public boolean negatesPermissionExactly(String permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");

        if(permissionPath.trim().endsWith(".*"))
        {
            permissionPath = permissionPath.substring(0, permissionPath.length() - 2);
            return negatesPermissionExactly(Arrays.asList(splitPath(permissionPath)), descendantPermissionTree);
        }

        return negatesPermissionExactly(splitPath(permissionPath));
    }

    /**
     * Checks if this permissions set specifically negates the provided permission path. That is, if the permission path
     * has been specifically added as one to negate.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if the permission path is explicitly negated. That is, if the path has been specifically added to
     *         this permission set as one that should be negated, and its negation isn't simply inferred from other
     *         permission that covers it. Otherwise, false.
     */
    public boolean negatesPermissionExactly(List<String> permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return negatesPermissionExactly(permissionPath, exactPermissionTree);
    }

    /**
     * Checks if this permissions set specifically negates the provided permission path. That is, if the permission path
     * has been specifically added as one to negate.
     * @param permissionPath The permission path to test, as an array of nodes.
     * @return True if the permission path is explicitly negated. That is, if the path has been specifically added to
     *         this permission set as one that should be negated, and its negation isn't simply inferred from other
     *         permission that covers it. Otherwise, false.
     */
    public boolean negatesPermissionExactly(String... permissionPath)
    {
        Objects.requireNonNull(permissionPath, "permissionPath must not be null.");
        return negatesPermissionExactly(Arrays.asList(permissionPath), exactPermissionTree);
    }

    /**
     * Checks if the given permission trees directly negate the given permission path.
     * @param permissionPath The path to check for.
     * @param permTree The regular permission tree to check.
     * @return True if the given trees contain a direct negating permission at the given path. Otherwise, false.
     */
    private static boolean negatesPermissionExactly(List<String> permissionPath, Tree<String, Permission> permTree)
    {
        Permission perm = permTree.getAtOrNull(new TreePath<>(permissionPath));
        return (perm != null) && (perm.negates()) && (!perm.isIndirect());
    }
    //endregion
    //endregion
    //endregion

    //region Conversion to strings
    /**
     * <p>Gets a string representation of the permission at the given path.</p>
     *
     * <p>Whether the permission at the given path needs to be represented by multiple lines, these will be concatenated
     * into the result.</p>
     * @param permPath The path to get a string representation of the permission at.
     * @return A string representation of the permission at the given path.
     */
    private String getSaveStringForPermission(List<String> permPath)
    {
        String[] lines = getSaveStringLinesForPermission(permPath);

        return lines.length == 0 ? ""
             : lines.length == 1 ? lines[0]
             :                     lines[0] + "\n" + lines[1];
    }

    /**
     * <p>Gets a string representation or string representations of the permission at a given path.</p>
     *
     * <p>Each member of the returned array is a savestring line. (ignoring the multi-line permission arguments.) Some
     * permissions may result in multiple lines needing to be used to represent it, such as where a path is allowed,
     * but anything underneath it (starting with it, but not equal to it) is negated.</p>
     * @param permPath The path of the permission to get a string representation or string representations of.
     * @return An array containing one or two strings, which are string representations of the permission at the given
     *         path.
     */
    private String[] getSaveStringLinesForPermission(List<String> permPath)
    { return getSaveStringLinesForPermission(permPath, true); }

    /**
     * <p>Gets a string representation or string representations of the permission at a given path.</p>
     *
     * <p>Each member of the returned array is a savestring line. (ignoring the multi-line permission arguments.) Some
     * permissions may result in multiple lines needing to be used to represent it, such as where a path is allowed,
     * but anything underneath it (starting with it, but not equal to it) is negated.</p>
     * @param permPath The path of the permission to get a string representation or string representations of.
     * @param includeArg Whether or not to include the permission argument in the string representation(s).
     * @return An array containing one or two strings, which are string representations of the permission at the given
     *         path.
     */
    private String[] getSaveStringLinesForPermission(List<String> permPath, boolean includeArg)
    {
        TreePath<String> pPath = new TreePath<>(permPath);
        Permission forExact = exactPermissionTree.getAtOrNull(pPath);
        Permission forDescendants = descendantPermissionTree.getAtOrNull(pPath);

        if(forExact == null && forDescendants == null)
            return new String[0];

        String pathJoined = (permPath.isEmpty()) ? ("*") : (String.join(".", permPath));

        if(forExact == null)
            return new String[] { applyPermissionToPathString(pathJoined + ".*", forDescendants, includeArg) };

        if(forDescendants == null)
        {
            throw new UnsupportedOperationException("Currently no syntax for permissions not including descendants."
                                                    + "\nPath: " + pathJoined);
        }

        if(forDescendants.isIndirect())
            return new String[] { applyPermissionToPathString(pathJoined, forExact, includeArg) };

        return new String[]
        {
                applyPermissionToPathString(pathJoined, forExact, includeArg),
                applyPermissionToPathString(pathJoined + ".*", forDescendants, includeArg)
        };
    }

    /**
     * Gets string representations of all permissions in this permission set. See {@link #toSaveString()} for details.
     * @param includeArgs Whether or not to include string arguments in the string representations of arguments.
     * @return A list, ordered by permission path, of string representations of permissions in this permission set.
     */
    public List<String> getPermissionsAsStrings(boolean includeArgs)
    {
        // TO DO: Rewrite this so the paths of exactPaths and descPaths are concatted together, sorted, then stringified
        //        using which of those two collections they came from. Don't need to worry about distinctness/splitting
        //        them into separate paths as both collections contain only direct permissions.

        Stream<List<String>> exactPaths = exactPermissionTree
                .getEntries()
                .stream()
                .map(x -> x.getPath().getNodes());

        Stream<List<String>> descPaths = descendantPermissionTree
                .getEntriesWhere(x -> !x.getItem().isIndirect())
                .stream()
                .map(x -> x.getPath().getNodes());

        List<String> result = new ArrayList<>();

        Stream.concat(exactPaths, descPaths)
              .distinct()
              .sorted(PATH_COMPARATOR)
              .forEachOrdered(path ->
        {
            String[] lines = getSaveStringLinesForPermission(path, includeArgs);

            if(lines.length >= 2)
            {
                result.add(lines[0]);
                result.add(lines[1]);
            }
            else if(lines.length >= 1)
            {
                result.add(lines[0]);
            }
        });

        return result;
    }

    /**
     * <p>Produces a possibly multi-line string representation of this permission set.</p>
     *
     * <p>Each line is a permission to be parsed, unless it's incremented with four spaces, in which case, it's a
     * continuation of the permission argument of the previous line's permission.</p>
     *
     * <p>Each added permission is represented by a dot-notated path.</p>
     * <ul>
     *     <il><p>This path may be suffixed with ".*" to indicate that it covers all permissions below it unless
     *     explicitly set themselves.</p></il>
     *     <il><p>This path may be prefixed with "-" to indicate that it negates any permissions it covers rather than
     *     allowing them.</p></il>
     *     <il><p>This path may be followed by a colon ":" - any text after the colon on the line, or indented four
     *     spaces on following lines until a line note indented by four spaces is found, is considered path of the
     *     argument passed to the permission, and is not part of the permission syntax itself.</p></il>
     * </ul>
     *
     * @return A string representation of this permission set.
     */
    public String toSaveString()
    {
        // TO DO: Rewrite this so the paths of exactPaths and descPaths are concatted together, sorted, then stringified
        //        using which of those two collections they came from. Don't need to worry about distinctness/splitting
        //        them into separate paths as both collections contain only direct permissions.

        StringBuilder sb = new StringBuilder();

        Stream<List<String>> exactPaths = exactPermissionTree
                .getEntries()
                .stream()
                .map(x -> x.getPath().getNodes());

        Stream<List<String>> descPaths = descendantPermissionTree
                .getEntriesWhere(x -> !x.getItem().isIndirect())
                .stream()
                .map(x -> x.getPath().getNodes());

        Stream.concat(exactPaths, descPaths)
              .distinct()
              .sorted(PATH_COMPARATOR)
              .forEachOrdered(path -> sb.append(getSaveStringForPermission(path)).append("\n"));

        return sb.length() == 0 ? sb.toString() : sb.substring(0, sb.length() - 1);
    }
    //endregion
    //endregion

    //region Mutators
    //region set
    /**
     * <p>Parses the provided permission as a string and adds it to the permission set.</p>
     *
     * <p>Permissions must be in the form of: "first.second.third"</p>
     *
     * <p>Permissions may be suffixed with ".*" to make it apply to all permissions lower than itself (starting with
     * it), but not to itself.</p>
     *
     * <p>Permissions may be prefixed with "-" to indicate that it negates the permission and any it covers, rather than
     * allowing them.</p>
     *
     * <p>Any text after the first colon ":" is considered to make up the string argument, and not be part of the
     * formatted permission itself.</p>
     * @param permissionAsString The permission formatted as a string.
     * @return The permission object previously set at the given path, or null if there was none.
     * @throws ParseException If the provided string is not parsable as a permission.
     */
    public Permission set(String permissionAsString) throws ParseException
    {
        Objects.requireNonNull(permissionAsString, "permissionAsString must not be null.");
        String[] parts = permissionAsString.split(":", 2);
        String permWithoutArg = parts[0].trim();
        String permArg = parts.length > 1 ? parts[1].trim() : null;
        Permission perm = createPermissionFromString(permWithoutArg, permArg);
        return storePermission(perm, permissionAsString, permWithoutArg);
    }

    /**
     * <p>Parses the provided permission as a string and adds it to the permission set, as described in
     * {@link #set(String)}, after having deïndented the string.</p>
     *
     * <p>This is specifically useful where a permission argument spans multiple lines and the format requires that such
     * arguments be indented 4 spades from the permission itself.</p>
     * @param permissionAsString The permission formatted as a string.
     * @return The permission object previously set at the given path, or null if there was none.
     * @throws ParseException If the provided string is not parsable as a permission.
     */
    public Permission setWhileDeIndenting(String permissionAsString) throws ParseException
    {
        Objects.requireNonNull(permissionAsString, "permissionAsString must not be null.");
        return set(permissionAsString.replaceAll("(?m)^ {4}", ""));
    }

    /**
     * <p>Creates a permission object from a path, and argument if applicable.</p>
     *
     * <p>Permissions are negating when their path starts with "-".</p>
     * @param pathAsString The path of the permission, including any decorations like negation, but without the
     *                     permission argument if applicable. (Anything after the colon)
     * @param permissionArgument The permission argument.
     * @return A new permission object derived from the parameters provided.
     */
    Permission createPermissionFromString(String pathAsString, String permissionArgument)
    {
        Permission perm = pathAsString.startsWith("-") ? Permission.NEGATING : Permission.PERMITTING;

        if(permissionArgument != null)
            perm = perm.withArg(permissionArgument);

        return perm;
    }

    /**
     * Stores a given permission object in the permission set at the given path.
     * @param permission The permission to store.
     * @param permissionAsString The original string representation of the permission being stored.
     * @param pathAsString The path at which the permission is being stored.
     * @return The permission object previously set at the given path, or null if there was none.
     * @throws ParseException If the provided string is not parsable as a permission.
     */
    Permission storePermission(Permission permission, String permissionAsString, String pathAsString)
            throws ParseException
    {
        if(pathAsString.startsWith("-"))
            pathAsString = pathAsString.substring(1);

        if(pathAsString.equals("*"))
        {
            Permission oldValue = exactPermissionTree.setRootItem(permission);
            descendantPermissionTree.setRootItemIf(permission.indirectly(),
                                                   (p, perm) -> (perm == null) || (perm.isIndirect()));
            return oldValue;
        }

        boolean isWildcard = false;

        if(pathAsString.endsWith(".*"))
        {
            isWildcard = true;
            pathAsString = pathAsString.substring(0, pathAsString.length() - 2);
        }

        if(pathAsString.contains("*"))
            throw new ParseException
            (
                "Permissions cannot be arbitrarily wildcarded: " + permissionAsString,
                permissionAsString.indexOf("*")
            );

        if(pathAsString.contains("-"))
            throw new ParseException
            (
                "Permission negations must be at the start of the permission: " + permissionAsString,
                permissionAsString.indexOf("-", permission.negates() ? 1 : 0)
            );

        TreePath<String> path = new TreePath<>(splitPath(pathAsString));
        Permission oldValue;

        if(!isWildcard)
        {
            oldValue = exactPermissionTree.setAt(path, permission);
            descendantPermissionTree.setAtIf(path, permission.indirectly(), (tp, p) -> (p == null) || (p.isIndirect()));
        }
        else // if isWildcard
            oldValue = descendantPermissionTree.setAt(path, permission);

        return oldValue;
    }
    //endregion

    //region remove
    /**
     * Removes the provided permission from the permission set.
     * @apiNote Negation and string arguments are not needed for removal, and are ignored.
     * @apiNote "some.thing" and "some.thing.*" are different permissions and removing one does not remove the other.
     * @apiNote This does not remove any permissions "lower than" (starting with) or "higher than" (truncated from) the
     *          provided permission.
     * @param permissionAsString The permission formatted as a string.
     * @return The permission object that was at the given path in the permission set, or null if there was none.
     */
    public Permission remove(String permissionAsString)
    {
        Objects.requireNonNull(permissionAsString, "permissionAsString must not be null.");
        permissionAsString = permissionAsString.trim();

        if(permissionAsString.contains(":"))
            permissionAsString = permissionAsString.substring(0, permissionAsString.indexOf(":")).trim();

        if(permissionAsString.startsWith("-"))
            permissionAsString = permissionAsString.substring(1).trim();

        boolean isForWildcard = false;

        if(permissionAsString.endsWith(".*"))
        {
            permissionAsString = permissionAsString.substring(0, permissionAsString.length() - 2).trim();
            isForWildcard = true;
        }

        TreePath<String> path = new TreePath<>(splitPath(permissionAsString));

        if(!isForWildcard)
        {
            Permission permissionThatWasThere = exactPermissionTree.clearAt(path);

            if(permissionThatWasThere != null)
            {
                Permission descendantPerm = descendantPermissionTree.getAtOrNull(path);

                if(descendantPerm != null && descendantPerm.isIndirect())
                    descendantPermissionTree.clearAt(path);
            }

            return permissionThatWasThere;
        }
        else
        {
            MutableWrapper<Boolean> removedFlag = new MutableWrapper<>(false);

            Permission permissionThatWasThere = descendantPermissionTree.clearAtIf(path, (xpath, xperm) ->
            {
                boolean isDirect = !xperm.isIndirect();
                removedFlag.set(isDirect);
                return isDirect;
            });

            return removedFlag.get() ? permissionThatWasThere : null;
        }
    }
    //endregion

    //region clear
    /**
     * Removes all permissions from this permission set.
     */
    public void clear()
    {
        exactPermissionTree.clear();
        descendantPermissionTree.clear();
    }
    //endregion
    //endregion
    //endregion
}
