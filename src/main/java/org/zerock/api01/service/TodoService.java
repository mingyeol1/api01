package org.zerock.api01.service;

import jakarta.transaction.Transactional;
import org.zerock.api01.dto.PageRequestDTO;
import org.zerock.api01.dto.PageResponseDTO;
import org.zerock.api01.dto.TodoDTO;

@Transactional
public interface TodoService {

        Long register(TodoDTO todoDTO);

        TodoDTO read(Long tno);

        PageResponseDTO<TodoDTO> list(PageRequestDTO pageRequestDTO);

        void remove(Long tno);

        void modify(TodoDTO todoDTO);
}
