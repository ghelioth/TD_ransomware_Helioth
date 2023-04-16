# TD_ransomware_Helioth

# Réponses aux Questions : 

## Question 1 : 
Le nom de l'algorithme de chiffrement utilisé dans le code est XOR (ou exclusive OR). C'est un algorithme de chiffrement simple, qui est souvent utilisé pour des tâches de cryptage simples.

Le chiffrement XOR n'est pas considéré comme très robuste, car il est facilement cassable par des attaques de force brute. De plus, la clé utilisée dans cet algorithme est cyclique, ce qui peut rendre le chiffrement encore plus vulnérable aux attaques.

Donc, le chiffrement XOR est considéré comme un algorithme de chiffrement faible et n'est donc pas recommandé pour les applications de sécurité qui nécessitent une protection forte des données.


## Question  2 : 
Parce que il ne faut pas mélanger le sel et la clé directement car ça les rend vulnérables à des attaques informatiques. Le sel est utilisé pour rendre plus difficile la recherche de la clé originale. En ajoutant le sel avant de hasher, on augmente la sécurité en rendant plus difficile la recherche de la clé.

Et utiliser un HMAC est une bonne idée pour renforcer la sécurité des clés. Cela crée un code secret pour chaque message qui assure que la clé n'a pas été modifiée. Mais il est important d'utiliser un sel pour renforcer la sécurité de la clé.