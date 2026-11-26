import { Schema } from "effect"
import { Ipc } from "@opencode/plugin/gui"

const AnswerValue = Schema.Union([
  Schema.String,
  Schema.Number,
  Schema.Boolean,
  Schema.Array(Schema.String),
])

const AnswerEntry = Schema.Struct({
  key: Schema.String,
  value: AnswerValue,
})

/**
 * GUI main-process bridge for OpenCode question forms. A server plugin can
 * read `form.created` but cannot call `session.form.reply`; the desktop GUI
 * owns that client method. Email answers cross this IPC to complete the form.
 */
export const QuestionBridge = Ipc.define({
  id: "autocrypt-bridge.question",
  methods: {
    reply: {
      input: Schema.Struct({
        sessionID: Schema.String,
        formID: Schema.String,
        answer: Schema.Array(AnswerEntry),
      }),
    },
  },
})
