package scot.massie.lib.permissions;

import scot.massie.lib.collections.tree.RecursiveTree;
import scot.massie.lib.collections.tree.Tree;

import java.text.ParseException;
import java.util.*;
import java.util.stream.Stream;

/**
 * A set of {@link Permission permissions} arranged in a string-keyed tree, where permissions are considered to "cover"
 * (apply to) all permissions under them in the tree.
 */
public final class PermissionSet
{
    //region initialisation
    public static final class PermissionWithPath
    {
        public PermissionWithPath(List<String> path, Permission perm)
        {
            this.path = path;
            this.permission = perm;
        }

        private final List<String> path;
        private final Permission permission;

        public List<String> getPath()
        { return path; }

        public Permission getPermission()
        { return permission; }
    }
    //endregion

    //region Static final values
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

    //region fields
    Tree<String, Permission> exactPermissionTree = new RecursiveTree<>();
    Tree<String, Permission> descendantPermissionTree = new RecursiveTree<>();
    //endregion

    //region static string manipulation methods
    private static String[] splitPath(String permissionPath)
    { return permissionPath.split("\\."); }

    private static String applyPermissionToPathStringWithoutArg(String path, Permission perm)
    { return perm.negates() ? ("-" + path) : path; }

    private static String applyPermissionToPathString(String path, Permission perm)
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

    private static String applyPermissionToPathString(String path, Permission perm, boolean includeArg)
    { return includeArg ? applyPermissionToPathString(path, perm) : applyPermissionToPathStringWithoutArg(path, perm); }
    //endregion

    //region Accessors
    //region tests as a whole

    /**
     * Checks whether or not this permission set contains any permissions at all.
     * @return True if this contains any permissions. Otherwise, false.
     */
    public boolean hasAny()
    { return !isEmpty(); }

    /**
     * Checks whether or not this permission set is empty.
     * @return True if this contains no permissions. Otherwise, false.
     */
    public boolean isEmpty()
    { return exactPermissionTree.isEmpty() && descendantPermissionTree.isEmpty(); }
    //endregion
    //region getters

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path, paired with the path it's
     * at.
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path, paired with the path of that
     *         permission in this permission set, in the form of a {@link PermissionWithPath}.
     */
    public PermissionWithPath getMostRelevantPermission(String permissionPath)
    { return getMostRelevantPermission(Arrays.asList(splitPath(permissionPath))); }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path, paired with the path it's
     * at.
     * @param permissionPath The permission path, as a list of nodes, to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path, paired with the path of that
     *         permission in this permission set, in the form of a {@link PermissionWithPath}.
     */
    public PermissionWithPath getMostRelevantPermission(List<String> permissionPath)
    {
        Permission relevantPerm = exactPermissionTree.getAtOrNull(permissionPath);

        if(relevantPerm != null)
            return new PermissionWithPath(permissionPath, relevantPerm);

        List<Tree.Entry<String, Permission>> relevantEntries = descendantPermissionTree.getEntriesAlong(permissionPath);

        if(relevantEntries.isEmpty())
            return null;

        int lastIndex = relevantEntries.size() - 1;
        Tree.Entry<String, Permission> relevantEntry = relevantEntries.get(lastIndex);

        if(relevantEntry.getPath().size() == permissionPath.size())
        {
            if(relevantEntries.size() <= 1)
                return null;

            relevantEntry = relevantEntries.get(lastIndex - 1);
        }

        return new PermissionWithPath(relevantEntry.getPath().getNodes(), relevantEntry.getItem());
    }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path, paired with the path it's
     * at.
     * @param permissionPath The permission path, as an array of nodes, to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path, paired with the path of that
     *         permission in this permission set, in the form of a {@link PermissionWithPath}.
     */
    public PermissionWithPath getMostRelevantPermission(String... permissionPath)
    { return getMostRelevantPermission(Arrays.asList(permissionPath)); }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path.
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path.
     */
    public Permission getPermission(String permissionPath)
    { return getPermission(Arrays.asList(splitPath(permissionPath))); }

    /**
     * Gets the {@link Permission} in this permission set that applies to the provided path.
     * @param permissionPath The permission path, as a list of nodes, to get the permission that applies to it.
     * @return The {@link Permission} that applies to the provided permission path.
     */
    public Permission getPermission(List<String> permissionPath)
    {
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
    { return getPermission(Arrays.asList(permissionPath)); }
    //endregion
    //region test permissions

    /**
     * Checks if the permissions in this permission set allow the provided permission.
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to test.
     * @return True if the permission path is allowed. Otherwise, false.
     */
    public boolean hasPermission(String permissionPath)
    { return hasPermission(Arrays.asList(splitPath(permissionPath))); }

    /**
     * Checks if the permissions in this permission set allow the provided permission.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if the permission path is allowed. Otherwise, false.
     */
    public boolean hasPermission(List<String> permissionPath)
    {
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && (mrp.permission.permits());
    }

    /**
     * Checks if the permissions in this permission set allow the provided permission.
     * @param permissionPath The permission path to test, as an array of nodes.
     * @return True if the permission path is allowed. Otherwise, false.
     */
    public boolean hasPermission(String... permissionPath)
    { return hasPermission(Arrays.asList(permissionPath)); }

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
    { return hasPermissionExactly(splitPath(permissionPath)); }

    /**
     * Checks if this permissions set explicitly allows the provided permission path, and the provided permission path
     * is not simply allowed by inference of another permission that covers it.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if the permission path is explicitly allowed. That is, if this specific path has been added as a
     *         permission, and isn't simply allowed by inference from another permission that covers this one.
     *         Otherwise, false.
     */
    public boolean hasPermissionExactly(List<String> permissionPath)
    { return exactPermissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.permits()); }

    /**
     * Checks if this permissions set explicitly allows the provided permission path, and the provided permission path
     * is not simply allowed by inference of another permission that covers it.
     * @param permissionPath The permission path to test, as an array of nodes.
     * @return True if the permission path is explicitly allowed. That is, if this specific path has been added as a
     *         permission, and isn't simply allowed by inference from another permission that covers this one.
     *         Otherwise, false.
     */
    public boolean hasPermissionExactly(String... permissionPath)
    { return exactPermissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.permits()); }

    /**
     * Checks if this permissions set negates the provided permission path. (and doesn't simply not cover it.)
     * @apiNote The permission path provided should not contain any negation or string argument, or be a wildcard
     *          permission. It should just be a simple permission path in the form of "this.is.some.permission".
     * @param permissionPath The permission path to test.
     * @return True if the permission path is negated. Otherwise, (including if this permission set doesn't allow the
     *         provided permission path by simple omission) false.
     */
    public boolean negatesPermission(String permissionPath)
    { return negatesPermission(Arrays.asList(splitPath(permissionPath))); }

    /**
     * Checks if this permissions set negates the provided permission path. (and doesn't simply not cover it.)
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if the permission path is negated. Otherwise, (including if this permission set doesn't allow the
     *         provided permission path by simple omission) false.
     */
    public boolean negatesPermission(List<String> permissionPath)
    {
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
    { return negatesPermission(Arrays.asList(permissionPath)); }

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
    { return negatesPermissionExactly(splitPath(permissionPath)); }

    /**
     * Checks if this permissions set specifically negates the provided permission path. That is, if the permission path
     * has been specifically added as one to negate.
     * @param permissionPath The permission path to test, as a list of nodes.
     * @return True if the permission path is explicitly negated. That is, if the path has been specifically added to
     *         this permission set as one that should be negated, and its negation isn't simply inferred from other
     *         permission that covers it. Otherwise, false.
     */
    public boolean negatesPermissionExactly(List<String> permissionPath)
    { return exactPermissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.negates()); }

    /**
     * Checks if this permissions set specifically negates the provided permission path. That is, if the permission path
     * has been specifically added as one to negate.
     * @param permissionPath The permission path to test, as an array of nodes.
     * @return True if the permission path is explicitly negated. That is, if the path has been specifically added to
     *         this permission set as one that should be negated, and its negation isn't simply inferred from other
     *         permission that covers it. Otherwise, false.
     */
    public boolean negatesPermissionExactly(String... permissionPath)
    { return exactPermissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.negates()); }
    //endregion
    //region conversion to savestrings
    private String getSaveStringForPermission(List<String> permPath)
    {
        String[] lines = getSaveStringLinesForPermission(permPath);

        return lines.length == 0 ? ""
                       : lines.length == 1 ? lines[0]
                                 :                     lines[0] + "\n" + lines[1];
    }

    private String[] getSaveStringLinesForPermission(List<String> permPath)
    { return getSaveStringLinesForPermission(permPath, true); }

    private String[] getSaveStringLinesForPermission(List<String> permPath, boolean includeArg)
    {
        Permission forExact = exactPermissionTree.getAtOrNull(permPath);
        Permission forDescendants = descendantPermissionTree.getAtOrNull(permPath);

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

    public List<String> getPermissionsAsStrings(boolean includeArgs)
    {
        Stream<List<String>> exactPaths = exactPermissionTree.getPaths().stream().map(x -> x.getNodes());
        Stream<List<String>> descendantPaths = descendantPermissionTree.getPaths().stream().map(x -> x.getNodes());
        List<String> result = new ArrayList<>();

        Stream.concat(exactPaths, descendantPaths)
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

    public String toSaveString()
    {
        StringBuilder sb = new StringBuilder();
        Stream<List<String>> exactPaths = exactPermissionTree.getPaths().stream().map(x -> x.getNodes());
        Stream<List<String>> descendantPaths = descendantPermissionTree.getPaths().stream().map(x -> x.getNodes());

        Stream.concat(exactPaths, descendantPaths)
              .distinct()
              .sorted(PATH_COMPARATOR)
              .forEachOrdered(path ->
                              {
                                  sb.append(getSaveStringForPermission(path)).append("\n");
                              });

        return sb.length() == 0 ? sb.toString() : sb.substring(0, sb.length() - 1);
    }
    //endregion
    //endregion

    //region Mutators

    /**
     * Parses the provided permission as a string and adds it to the permission set.
     *
     * Permissions must be in the form of: "first.second.third"
     *
     * Permissions may be suffixed with ".*" to make it apply to all permissions lower than itself (starting with it),
     * but not to itself.
     *
     * Permissions may be prefixed with "-" to indicate that it negates the permission and any it covers, rather than
     * allowing them.
     *
     * Any text after the first colon ":" is considered to make up the string argument, and not be part of the formatted
     * permission itself.
     * @param permissionAsString The permission formatted as a string.
     * @throws ParseException If the provided string is not parsable as a permission.
     */
    public void set(String permissionAsString) throws ParseException
    {
        boolean isNegation = false;
        boolean isWildcard = false;
        String[] parts = permissionAsString.split(":", 2);
        String permWithoutArg = parts[0].trim();
        String permArg = parts.length > 1 ? parts[1].trim() : null;

        if(permWithoutArg.startsWith("-"))
        {
            isNegation = true;
            permWithoutArg = permWithoutArg.substring(1);
        }

        Permission perm = isNegation ? Permission.NEGATING : Permission.PERMITTING;

        if(permArg != null)
            perm = perm.withArg(permArg);

        if(permWithoutArg.equals("*"))
        {
            exactPermissionTree.setRootItem(perm);
            descendantPermissionTree.setRootItemIf(perm.indirectly(), (p, has) -> !has || p.isIndirect());
            return;
        }

        if(permWithoutArg.endsWith(".*"))
        {
            isWildcard = true;
            permWithoutArg = permWithoutArg.substring(0, permWithoutArg.length() - 2);
        }

        if(permWithoutArg.contains("*"))
            throw new ParseException
                          (
                                  "Permissions cannot be arbitrarily wildcarded: " + permissionAsString,
                                  permissionAsString.indexOf("*")
                          );

        if(permWithoutArg.contains("-"))
            throw new ParseException
                          (
                                  "Permission negations must be at the start of the permission: " + permissionAsString,
                                  permissionAsString.indexOf("-", isNegation ? 1 : 0)
                          );

        String[] path = splitPath(permWithoutArg);

        if(!isWildcard)
        {
            exactPermissionTree.setAt(perm, path);
            descendantPermissionTree.setAtIf(perm.indirectly(), path, (p, has) -> !has || p.isIndirect());
        }
        else // if isWildcard
            descendantPermissionTree.setAt(perm, path);
    }

    /**
     * Parses the provided permission as a string and adds it to the permission set, as described in
     * {@link #set(String)}, after having deïndented the string.
     *
     * This is specifically useful where a permission argument spans multiple lines and the format requires that such
     * arguments be indented 4 spades from the permission itself.
     * @param permissionAsString The permission formatted as a string.
     * @throws ParseException If the provided string is not parsable as a permission.
     */
    public void setWhileDeIndenting(String permissionAsString) throws ParseException
    { set(permissionAsString.replaceAll("(?m)^ {4}", "")); }

    /**
     * Removes the provided permission from the permission set.
     * @apiNote Negation and string arguments are not needed for removal, and are ignored.
     * @apiNote "some.thing" and "some.thing.*" are different permissions and removing one does not remove the other.
     * @apiNote This does not remove any permissions "lower than" (starting with) the provided permission.
     * @param permissionAsString The permission formatted as a string.
     * @return True if the permission set was changed as a result of this call. Otherwise, false.
     */
    public boolean remove(String permissionAsString)
    {
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

        String[] path = splitPath(permissionAsString);

        if(!isForWildcard)
        {
            if(exactPermissionTree.clearAt(path).valueWasPresent())
            {
                Permission descendantPerm = descendantPermissionTree.getAtOrNull(path);

                if(descendantPerm != null && descendantPerm.isIndirect())
                    descendantPermissionTree.clearAt(path);

                return true;
            }
            else
                return false;
        }
        else
            return descendantPermissionTree.clearAt(path).valueWasPresent();
    }

    /**
     * Removes all permissions from this permission set.
     */
    public void clear()
    {
        exactPermissionTree.clear();
        descendantPermissionTree.clear();
    }
    //endregion
}
