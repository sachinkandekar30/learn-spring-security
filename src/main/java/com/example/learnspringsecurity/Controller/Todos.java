package com.example.learnspringsecurity.Controller;

import jakarta.annotation.security.RolesAllowed;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.stream.Collectors;

@RestController
@CrossOrigin(origins = "http://localhost:300")
public class Todos {

    private Logger logger = LoggerFactory.getLogger(getClass());
    public final static List<Todo> LIST_OF_TODO =
            List.of(new Todo("user","learning is continues  process")
            ,new Todo("Saanvi","Enjoy learning is continues  process"));

    @GetMapping("/todos")
    public List<Todo> getAllTodos(){
        return LIST_OF_TODO;
    }

    @GetMapping("/users/{username}/todos")
    //Below code is is foe Enable method security in spring security

    @PreAuthorize(("hasRole('USER') and  #username==authentication.name"))
    @PostAuthorize("returnObject.userName=='user'")
    //this setting we can do when JSR-250 is enable  like @EnableMethodSecurity(jsr250Enabled = true)
    @RolesAllowed({"ADMIN","USER"})
    //this setting we can do when securedEnabled=true this is old srpig  enable  like @EnableMethodSecurity(securedEnabled = true)
    @Secured({"ROLE_ADMIN","ROLE_USER"}) // It is checking agains auhority

    public Todo getUserSpecificTodo(@PathVariable String username) {
        return LIST_OF_TODO.stream().filter(a -> a.userName().equalsIgnoreCase(username)).toList().get(0);
    }

    @PostMapping("/users/{username}/todos")
    public void addRecord(@PathVariable String username,
                          @RequestBody Todo todo){

        logger.info("Creating the {} for {} user",todo,username);


    }
}
record Todo(String userName,String Description){}
