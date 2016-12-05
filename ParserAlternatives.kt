package parser

import org.w3c.dom.Node


fun threat1(node: Node, version: TMVersion): Threat {
    val ID = findInChildren(node, TM_NODE_KEY).textContent
    val valNode = findInChildren(node, TM_NODE_VALUE)
    fun create(e: (k: String) -> String): Threat = Threat(id = ID,
            interaction = e("InteractionString"),
            category = e("UserThreatCategory"),
            title = e("Title"),
            description = e("UserThreatDescription"),
            state = e("StateInformation"))

    fun tm7(): Threat {
        val props = properties(valNode)
        fun extract(prop: String) = props.getOrElse(prop) { "" }
        return create(::extract)
    }

    fun tm4(): Threat {
        fun extract(prop: String): String = findInChildren(valNode, prop).textContent
        return create(::extract)
    }

    return mapOf(TMVersion.V2014 to ::tm4, TMVersion.V2016 to ::tm7)[version]!!.invoke()
}

fun threat2(node: Node, version: TMVersion): Threat {
    val ID = findInChildren(node, TM_NODE_KEY).textContent
    val valNode = findInChildren(node, TM_NODE_VALUE)
    fun create(e: (k: String) -> String): Threat = Threat(id = ID,
            interaction = e("InteractionString"),
            category = e("UserThreatCategory"),
            title = e("Title"),
            description = e("UserThreatDescription"),
            state = e("StateInformation"))


    fun tm7(): (String) -> String {
        return fun (prop: String) = properties(valNode).getOrElse(prop) { "" }
    }

    fun tm4(): (String) -> String {
        return fun(prop: String): String = findInChildren(valNode, prop).textContent
    }

    return create(mapOf(TMVersion.V2014 to ::tm4, TMVersion.V2016 to ::tm7)[version]!!())
}

fun threat3(node: Node, version: TMVersion): Threat {
    val ID = findInChildren(node, TM_NODE_KEY).textContent
    val valNode = findInChildren(node, TM_NODE_VALUE)

    return when(version){
        TMVersion.V2014 -> {
            fun e(prop: String): String = findInChildren(valNode, prop).textContent
            Threat(id = ID,
                    interaction = e("InteractionString"),
                    category = e("UserThreatCategory"),
                    title = e("Title"),
                    description = e("UserThreatDescription"),
                    state = e("StateInformation"))
        }
        TMVersion.V2016 -> {
            val props = properties(valNode)
            fun e(prop: String) = props.getOrElse(prop) { "" }
            Threat(id = ID,
                    interaction = e("InteractionString"),
                    category = e("UserThreatCategory"),
                    title = e("Title"),
                    description = e("UserThreatDescription"),
                    state = e("StateInformation"))
        }
    }
}

