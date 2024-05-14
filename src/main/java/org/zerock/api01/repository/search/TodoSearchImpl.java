package org.zerock.api01.repository.search;

import com.querydsl.core.BooleanBuilder;
import com.querydsl.core.types.Projections;
import com.querydsl.jpa.JPQLQuery;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.jpa.repository.support.QuerydslRepositorySupport;
import org.zerock.api01.domain.QTodo;
import org.zerock.api01.domain.Todo;
import org.zerock.api01.dto.PageRequestDTO;
import org.zerock.api01.dto.TodoDTO;
import org.zerock.api01.service.TodoServiceImpl;

import java.util.List;

public class TodoSearchImpl extends QuerydslRepositorySupport implements TodoSearch {

    public TodoSearchImpl() {
        super(Todo.class);
    }

    @Override
    public Page<TodoDTO> list(PageRequestDTO pageRequestDTO) {

        QTodo todo = QTodo.todo;

        JPQLQuery<Todo> query = from(todo); //select * from

        if (pageRequestDTO.getFrom() != null && pageRequestDTO.getTo() != null) {
            BooleanBuilder fromToBuilder = new BooleanBuilder();
            fromToBuilder.and(todo.dueDate.goe(pageRequestDTO.getFrom()));//~ 이상 이거나 같은경우
            fromToBuilder.and(todo.dueDate.loe(pageRequestDTO.getTo())); //~ 이하 이거나 같은경우
            query.where(fromToBuilder);
        }

        if (pageRequestDTO.getCompleted() != null){
            query.where(todo.complete.eq(pageRequestDTO.getCompleted()));
        }

        if (pageRequestDTO.getKeyword() != null){
            query.where(todo.title.contains(pageRequestDTO.getKeyword()));
        }

        this.getQuerydsl().applyPagination(pageRequestDTO.getPageable("tno"), query);
        JPQLQuery<TodoDTO> dtoQuery = query.select(Projections.bean(TodoDTO.class,
                todo.tno,
                todo.title,
                todo.dueDate,
                todo.complete,
                todo.writer
        ));

        List<TodoDTO> list = dtoQuery.fetch();
        long count = dtoQuery.fetchCount();

        return new PageImpl<>(list, pageRequestDTO.getPageable("tno"),count);
    }
}