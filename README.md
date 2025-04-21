
void test_func() {
    __asm(
        mov rdi, rax
    )
}

SimpleInjector inject;

inject.m_targetProcess = [proccess id]
inject.m_targetId= [target id]
inject.injectFunction([Memory address], &test_func);
