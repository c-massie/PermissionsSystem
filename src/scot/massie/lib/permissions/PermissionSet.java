package scot.massie.lib.permissions;

import scot.massie.lib.collections.tree.Tree;
import scot.massie.lib.collections.tree.RecursiveTree;
import java.text.ParseException;
import java.util.Arrays;
import java.util.List;

public final class PermissionSet
{
    Tree<String, Permission> permissionTree = new RecursiveTree<>();

    protected String[] splitPath(String permissionPath)
    { return permissionPath.split("\\."); }

    public void add(String permissionAsString) throws ParseException
    {
        boolean isNegation = false;
        boolean isWildcard = false;
        String[] parts = permissionAsString.split(":", 2);
        String permWithoutArg = parts[0];
        String permArg = parts.length > 1 ? parts[1] : null;

        if(permWithoutArg.startsWith("-"))
        {
            isNegation = true;
            permWithoutArg = permWithoutArg.substring(1);
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

        String[] nodes = permWithoutArg.split("\\.");
        permissionTree.setAt(new Permission(isNegation, isWildcard, permArg), nodes);
    }

    private Permission getMostRelevantPermission(List<String> permissionPath)
    {
        List<Tree.Entry<String, Permission>> relevantPerms = permissionTree.getEntriesAlong(permissionPath);

        if(relevantPerms.isEmpty())
            return null;

        // mrp = most relevant permission
        Tree.Entry<String, Permission> mrpWithPath = relevantPerms.get(relevantPerms.size() - 1);
        Permission mrp = mrpWithPath.getItem();
        Tree.TreePath<String> mrpPath = mrpWithPath.getPath();

        if((mrpPath.size() == permissionPath.size()) && (mrp.isWildcard()))
        {
            if(relevantPerms.size() <= 1)
                return null;

            mrp = relevantPerms.get(relevantPerms.size() - 2).getItem();
        }

        return mrp;
    }

    public boolean hasPermission(String permissionPath)
    { return hasPermission(Arrays.asList(splitPath(permissionPath))); }

    public boolean hasPermission(List<String> permissionPath)
    {
        Permission mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && (!mrp.isNegation());
    }

    public boolean hasPermission(String... permissionPath)
    { return hasPermission(Arrays.asList(permissionPath)); }

    public boolean hasPermissionExactly(String permissionPath)
    { return hasPermissionExactly(splitPath(permissionPath)); }

    public boolean hasPermissionExactly(List<String> permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && !perm.isNegation()); }

    public boolean hasPermissionExactly(String... permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && !perm.isNegation()); }

    public boolean negatesPermission(String permissionPath)
    { return negatesPermission(Arrays.asList(splitPath(permissionPath))); }

    public boolean negatesPermission(List<String> permissionPath)
    {
        Permission mrp = getMostRelevantPermission(permissionPath);
        return (mrp != null) && (mrp.isNegation());
    }

    public boolean negatesPermission(String... permissionPath)
    { return negatesPermission(Arrays.asList(permissionPath)); }

    public boolean negatesPermissionExactly(String permissionPath)
    { return negatesPermissionExactly(splitPath(permissionPath)); }

    public boolean negatesPermissionExactly(List<String> permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.isNegation()); }

    public boolean negatesPermissionExactly(String... permissionPath)
    { return permissionTree.getAtSafely(permissionPath).matches((has, perm) -> has && perm.isNegation()); }
}
