# Ejecutar
```bash                                                                                                                      Agregar módulo para encontrar        █  
                                                                                                                                           reverse shell                        █  
     # Normal (callback ON, wordlist embebida)                                                                                                                                  █  
     python main.py http://target.com                                                                                                      Context                              █  
                                                                                                                                           57,342 tokens                        █  
     # Sin callback server                                                                                                                 45% used                             █  
     python main.py http://target.com --no-callback                                                                                        $0.00 spent                          █  
                                                                                                                                                                                █  
     # Con wordlist externa                                                                                                                LSP                                  █  
     python main.py http://target.com --wordlist /path/to/wordlist.txt                                                                     • pyright                            █  
                                                                                                                                                                                ▀  
     # Combinado                                                                                                                           ▼ Modified Files                        
     python main.py http://target.com --no-callback --wordlist common.txt         
```