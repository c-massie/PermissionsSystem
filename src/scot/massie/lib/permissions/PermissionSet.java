package scot.massie.lib.permissions;

import scot.massie.lib.collections.tree.RecursiveTree;
import scot.massie.lib.collections.tree.Tree;

import java.text.ParseException;
import java.util.*;
import java.util.stream.Stream;

public final class PermissionSet
{
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

    Tree<String, Permission> exactPermissionTree = new RecursiveTree<>();
    Tree<String, Permission> descendantPermissionTree = new RecursiveTree<>();

    static final Comparator<List<String>> pathComparator = (a, b) ->
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

    protected String[] splitPath(String permissionPath)
    { return permissionPath.split("\\."); }

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

    public void setWhileDeIndenting(String permissionAsString) throws ParseException
    { set(permissionAsString.replaceAll("(?m)^ {4}", "")); }

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

    public boolean hasAny()
    { return !isEmpty(); }

    public boolean isEmpty()
    { return exactPermissionTree.isEmpty() && descendantPermissionTree.isEmpty(); }

    public PermissionWithPath getMostRelevantPermission(String permissionPath)
    { return getMostRelevantPermission(Arrays.asList(splitPath(permissionPath))); }

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

    public PermissionWithPath getMostRelevantPermission(String... permissionPath)
    { return getMostRelevantPermission(Arrays.asList(permissionPath)); }

    public Permission getPermission(String permissionPath)
    { return getPermission(Arrays.asList(splitPath(permissionPath))); }

    public Permission getPermission(List<String> permissionPath)
    {
        PermissionWithPath mostRelevant = getMostRelevantPermission(permissionPath);

        if(mostRelevant == null)
            return null;

        return mostRelevant.getPermission();
    }

    public Permission getPermission(String... permissionPath)
    { return getPermission(Arrays.asList(permissionPath)); }

    public boolean hasPermission(String permissionPath)
    { return hasPermission(Arrays.asList(splitPath(permissionPath))); }

    public boolean hasPermission(List<String> permissionPath)
    {
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && (mrp.permission.permits());
    }

    public boolean hasPermission(String... permissionPath)
    { return hasPermission(Arrays.asList(permissionPath)); }

    public boolean hasPermissionExactly(String permissionPath)
    { return hasPermissionExactly(splitPath(permissionPath)); }

    public boolean hasPermissionExactly(List<String> permissionPath)
    { return exactPermissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.permits()); }

    public boolean hasPermissionExactly(String... permissionPath)
    { return exactPermissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.permits()); }

    public boolean negatesPermission(String permissionPath)
    { return negatesPermission(Arrays.asList(splitPath(permissionPath))); }

    public boolean negatesPermission(List<String> permissionPath)
    {
        PermissionWithPath mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && (mrp.permission.negates());
    }

    public boolean negatesPermission(String... permissionPath)
    { return negatesPermission(Arrays.asList(permissionPath)); }

    public boolean negatesPermissionExactly(String permissionPath)
    { return negatesPermissionExactly(splitPath(permissionPath)); }

    public boolean negatesPermissionExactly(List<String> permissionPath)
    { return exactPermissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.negates()); }

    public boolean negatesPermissionExactly(String... permissionPath)
    { return exactPermissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.negates()); }

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

    private static String applyPermissionToPathStringWithoutArg(String path, Permission perm)
    { return perm.negates() ? ("-" + path) : path; }

    private static String applyPermissionToPathString(String path, Permission perm, boolean includeArg)
    { return includeArg ? applyPermissionToPathString(path, perm) : applyPermissionToPathStringWithoutArg(path, perm); }

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
              .sorted(pathComparator)
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
              .sorted(pathComparator)
              .forEachOrdered(path ->
        {
            sb.append(getSaveStringForPermission(path)).append("\n");
        });

        return sb.length() == 0 ? sb.toString() : sb.substring(0, sb.length() - 1);
    }
}
