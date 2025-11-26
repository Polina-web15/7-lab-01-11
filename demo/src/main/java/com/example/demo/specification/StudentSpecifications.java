package com.example.demo.specification;

import org.springframework.data.jpa.domain.Specification;

import com.example.demo.model.Student;

public class StudentSpecifications {
    private static Specification<Student> nameLike(String name){
        return (root, query, criteriaBuilder)->{
            if (name==null||name.trim().isEmpty()){
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.like(
                criteriaBuilder.lower(root.get("name")),
                "%"+name.trim().toLowerCase()+"%"
            );
        };
    }
    public static Specification<Student> groupNameEquals(String groupName) {
        return (root, query, criteriaBuilder) -> {
            if (groupName == null || groupName.trim().isEmpty()) {
                return criteriaBuilder.conjunction();
            }
            return criteriaBuilder.equal(
                    root.get("groupName"),
                    groupName.trim()
            );
        };
    }
    public static Specification<Student> filter(String name, String groupName){
        return Specification.allOf(nameLike(name),groupNameEquals(groupName));
        
    }
}
