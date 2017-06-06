package io.crate.sql.tree;


import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

public class Privilege extends Node {

    public enum PrivilegeType {
        DQL("DQL"),
        DML("DML"),
        DDL("DDL");

        private final String name;

        PrivilegeType(String name){
            this.name = name;
        }

        public boolean equalsName(String otherName) {
            return name.equals(otherName);
        }

        public String toString(){
            return this.name;
        }
    }

    private final PrivilegeType type;

    public Privilege(PrivilegeType type) {
        this.type = type;
    }

    public PrivilegeType type() {
        return type;
    }

    public static List<Privilege> getALL() {
        List <Privilege> allPrivileges = new ArrayList<Privilege>();
        allPrivileges.add(new Privilege(PrivilegeType.DDL));
        allPrivileges.add(new Privilege(PrivilegeType.DML));
        allPrivileges.add(new Privilege(PrivilegeType.DQL));
        return allPrivileges;
    }

    @Override
    public <R, C> R accept(AstVisitor<R, C> visitor, C context) {
        return visitor.visitPrivilege(this, context);
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        final Privilege that = (Privilege) o;
        return Objects.equals(this.type, that.type);
    }

    @Override
    public int hashCode() {
        return Objects.hash(type);
    }

    @Override
    public String toString() {
        return "Privilege{" +
            "type=" + type +
            '}';
    }
}
