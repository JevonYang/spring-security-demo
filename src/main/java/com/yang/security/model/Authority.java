package com.yang.security.model;

/**
 *
 * This class was generated by MyBatis Generator.
 * This class corresponds to the database table authority
 *
 * @mbg.generated do_not_delete_during_merge
 */
public class Authority {
    /** id*/
    private Long id;

    /** 权限名称*/
    private String name;

    /** 权限值*/
    private String value;

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column authority.id
     *
     * @return the value of authority.id
     *
     * @mbg.generated
     */
    public Long getId() {
        return id;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column authority.id
     *
     * @param id the value for authority.id
     *
     * @mbg.generated
     */
    public void setId(Long id) {
        this.id = id;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column authority.name
     *
     * @return the value of authority.name
     *
     * @mbg.generated
     */
    public String getName() {
        return name;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column authority.name
     *
     * @param name the value for authority.name
     *
     * @mbg.generated
     */
    public void setName(String name) {
        this.name = name;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method returns the value of the database column authority.value
     *
     * @return the value of authority.value
     *
     * @mbg.generated
     */
    public String getValue() {
        return value;
    }

    /**
     * This method was generated by MyBatis Generator.
     * This method sets the value of the database column authority.value
     *
     * @param value the value for authority.value
     *
     * @mbg.generated
     */
    public void setValue(String value) {
        this.value = value;
    }
}